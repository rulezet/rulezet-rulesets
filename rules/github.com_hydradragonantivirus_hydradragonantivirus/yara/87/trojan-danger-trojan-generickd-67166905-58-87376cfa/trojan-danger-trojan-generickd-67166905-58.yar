rule Trojan_Danger_Trojan_GenericKD_67166905_58 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.67166905_58.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d0f4b4776b220b47288ef16b1974b2601c6032b5f00a3589ac6f1e57594fb428"

  strings:
    $s1 = "Microsoft Office InfoPath 2007.lnk" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}