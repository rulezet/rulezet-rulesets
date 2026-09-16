rule sus_nsis_tampered_signature: TESTING SUSPICIOUS TA0005 T1027 T1027_005 {
  meta:
    id             = "7tGWOPTZRLhRAMCf6cQC0"
    fingerprint    = "082b47efe4dbb5ff515f2db759233fc39238bf4982aa0884b809232686c49531"
    version        = "1.0"
    creation_date  = "2023-06-01"
    first_imported = "2023-06-01"
    last_modified  = "2023-06-01"
    status         = "TESTING"
    sharing        = "TLP:WHITE"
    source         = "THEDFIRREPORT.COM"
    author         = "Maxime THIEBAUT (@0xThiebaut)"
    description    = "Detects a suspected Nullsoft Scriptable Install System (NSIS) executable with a tampered compiler signature"
    category       = "TOOL"
    tool           = "NSIS"
    mitre_att      = "T1027.005"
    reference      = "https://thedfirreport.com/"
    hash           = "121a1f64fff22c4bfcef3f11a23956ed403cdeb9bdb803f9c42763087bd6d94e"

  strings:
    $brand_error          = "NSIS Error" fullword
    $brand_description    = "Nullsoft Install System" fullword
    $brand_name           = "Nullsoft.NSIS" fullword
    $brand_url            = "http://nsis.sf.net/NSIS_Error" fullword
    $code_get_module      = {
      C1 E6 03                 8B BE ?? ?? ?? ??        57                       FF 15 ?? ?? ?? ??        85 C0                    75 ??                  }
    $code_get_proc        = {
      FF B6 ?? ?? ?? ??        50                       FF 15 ?? ?? ?? ??        EB ??                  }
    $code_jump_table      = {
      8B 4D ??                    83 C1 ??                    83 F9 ??                    0F 87 ?? ?? 00 00           FF 24 8D ?? ?? ?? 00      }
    $signature_1_00       = { EF BE AD DE 6E 73 69 73 69 6E 73 74 61 6C 6C 00 }
    $signature_1_00_check = {
      81 7D ?? EF BE AD DE        75 ??                       81 7D ?? 61 6C 6C 00        75 ??                       81 7D ?? 69 6E 73 74        75 ??                       81 7D ?? 6E 73 69 73        75 ??                     }
    $signature_1_1e       = { ED BE AD DE 4E 75 6C 6C 53 6F 66 74 49 6E 73 74 }
    $signature_1_1e_check = {
      81 7D ?? ED BE AD DE        75 ??                       81 7D ?? 49 6E 73 74        75 ??                       81 7D ?? 53 6F 66 74        75 ??                       81 7D ?? 4E 75 6C 6C        75 ??                     }
    $signature_1_30       = { EF BE AD DE 4E 75 6C 6C 53 6F 66 74 49 6E 73 74 }
    $signature_1_30_check = {
      81 7D ?? EF BE AD DE        75 ??                       81 7D ?? 49 6E 73 74        75 ??                       81 7D ?? 53 6F 66 74        75 ??                       81 7D ?? 4E 75 6C 6C        75 ??                     }
    $signature_1_60       = { EF BE AD DE 4E 75 6C 6C 73 6F 66 74 49 6E 73 74 }
    $signature_1_60_check = {
      81 7D ?? EF BE AD DE        75 ??                       81 7D ?? 49 6E 73 74        75 ??                       81 7D ?? 73 6F 66 74        75 ??                       81 7D ?? 4E 75 6C 6C        75 ??                     }

  condition:
    uint16(0) == 0x5A4D and (3 of ($brand_*) or 2 of ($code_*)) and none of ($signature_*)
}