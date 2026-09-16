rule Virus_Hijack_Gen_Trojan_ShellObject_fWW_a41FOHj_2_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.fWW@a41FOHj_2_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "41bc22d69070da500e58e0e493dd6d39dcb03679277dff05f893b6f7fc60867b"

  strings:
    $s1 = "Y@function time(){return new Date().getTime()}" fullword ascii
    $s2 = "\"><a class=\"radio-box\" href=\"javascript:void(0);\">500<i class=\"icon-check\"></i></a></label>" fullword ascii
    $s3 = "<embed autoplay=\"true\" src=\"sound.mp3\"  width=\"1\" height=\"1\" />" fullword ascii
    $s4 = "function time(){return Math.random()}" fullword ascii
    $s5 = "<label class=\"selected\" data-action=\"updateAmount\" data-value=\"" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}