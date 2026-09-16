rule Virus_Hijack_Gen_Trojan_ShellObject_m8Z_a4IIY9p_1_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.m8Z@a4IIY9p_1_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3eb187ed6df78c3744321e292c352aba3ac98f5f947f6b34b5997927e3ce4b0c"

  strings:
    $s1 = "dfKOqIsFgXk0K6X4Wm.qo0B7OXkfOJStrhkti+UjSMsStfwNijQAaSQ5+hyxdi8UTRB5r1cIVqT`1[[System.Object, mscorlib, Version=4.0.0.0, Culture" ascii
    $s2 = "<Module>{346FE479-2329-454B-85AD-3D226D1B8524}" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}