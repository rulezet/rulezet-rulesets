rule Virus_Hijack_Gen_Trojan_ShellObject_g8W_aOqOUDe_1_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8W@aOqOUDe_1_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2a3a16c3bd3ac6a77d057ba100393a9473a793e08ecad9131ec62821d5d75f84"

  strings:
    $s1 = "User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)" fullword ascii
    $s2 = "if exist \"%s\" goto :DELFILE" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}