rule Trojan_Danger_Trojan_GenericKD_67166905_153_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.67166905_153_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ec0976ee61ca281cf7f0355a5320bd03cb293be34ae7767be394350d056bdb89"

  strings:
    $s1 = "cWhat if Microsoft breaches its warranty? If Microsoft breaches its limited warranty, your only" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}