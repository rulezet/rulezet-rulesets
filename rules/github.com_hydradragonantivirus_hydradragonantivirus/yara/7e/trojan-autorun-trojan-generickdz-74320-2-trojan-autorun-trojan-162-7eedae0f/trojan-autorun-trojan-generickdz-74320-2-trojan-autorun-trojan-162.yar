import "pe"
rule _Trojan_Autorun_Trojan_GenericKDZ_74320_2_Trojan_Autorun_Trojan__162 {
  meta:
    description = "datamaliciousorder - from files Trojan.Autorun_Trojan.GenericKDZ.74320_2.vir, Trojan.Autorun_Trojan.GenericKDZ.74320_27.vir, Trojan.Danger_Trojan.GenericKD.72853156_318_1.vir, Trojan.Danger_Trojan.GenericKD.72853156_324_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cfdbab85abc6359dd930a51758e8a12ad261b2f7d8b9e119584fdc25fef00e19"
    hash2       = "86cb3a6e06c0faa5c1f55f737e49b3467ad2ffa1411668fe41883dad784015ae"
    hash3       = "5142d662f14bdc2f69c3639ec3e7c45584ad927bb8e7378379b91852d9675378"
    hash4       = "f24b6e17978cd0c5b77f1bdaec4d07f5453e7f693fb79dc61880d92efeb0f872"

  strings:
    $x1  = "C:\\Users\\user\\AppData\\Roaming\\Microsoft\\Internet Explorer\\Quick Launch\\User Pinned" fullword wide
    $x2  = "C:\\Windows\\system32\\x264vfw64.dll\",Configure" fullword wide
    $s3  = ":\\Users\\Public\\Desktop\\Acrobat Reader DC.lnk" fullword wide
    $s4  = "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Microsoft .NET Framework SDK v1.1" fullword wide
    $s5  = "Share Specific Users" fullword wide
    $s6  = "delegate folder that appears in Users Files Folder" fullword wide
    $s7  = "Shared Task Scheduler" fullword wide
    $s8  = "Inplace Share Engine" fullword wide
    $s9  = "\\\\?\\STORAGE#Volume#{a88738f5-f445-11e4-acbb-806e6f6e6963}#0000000000100000#{53f5630d-b6bf-11d0-94f2-00a0c91efb8b}" fullword wide
    $s10 = "\\\\?\\STORAGE#Volume#{a88738f5-f445-11e4-acbb-806e6f6e6963}#0000003D2E700000#{53f5630d-b6bf-11d0-94f2-00a0c91efb8b}" fullword wide
    $s11 = "\\\\?\\STORAGE#Volume#_??_IDE#DiskMass_Storage_Device_____________________ST6OA31B#5&2117b2e5&0&1.0.0#{53f56307-b6bf-11d0-94f2-0" wide
    $s12 = "Web History" fullword wide
    $s13 = "name Microsoft.EaseOfAccessCenter" fullword wide
    $s14 = "CompatContextMenu Class" fullword wide
    $s15 = "ook Window Class" fullword wide

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "d3cbd6e8f81da85f6bf0529e69de9251" and (1 of ($x*) and 4 of them)
    ) or (all of them)
}