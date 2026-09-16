rule sig_20160517_3886f333281ca5519dc538175b4594b7 {
  meta:
    description = "datamaliciousorder - file 20160517_3886f333281ca5519dc538175b4594b7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "efd50abb48ac6f231e7cd11e0684139c2110304e361a99c22ede64e0126500a4"

  strings:
    $s1 = "var geu='vjlvstavzumlrplprq eqeoleqi1hsybr2hogxrawjyzdjsulamfodbmbyfumzkdjwhe3n1k=q2bfy\\'adb3ztu2lfqcrgwrpnabaxpifwsnxfxtzh3uh1" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}