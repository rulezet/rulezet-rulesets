rule Trojan_Autorun_Trojan_GenericKDZ_94847_310_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKDZ.94847_310_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5339e7e6c50e79212fc12fb4096c6cdeb198f89ed6e6c3d240c6f2b55c99695f"

  strings:
    $s1 = "fyou received the software, and also any Microsoft updates, supplements, and services for the software," fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}