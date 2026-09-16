rule sig_20160525_42ef658cde155b1681a4b921271a7773 {
  meta:
    description = "datamaliciousorder - file 20160525_42ef658cde155b1681a4b921271a7773.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a6892ea88f2d32195564bdd06c47f0b6a8af2b054df7387cb205d7d612aab65a"

  strings:
    $s1 = "loch(suidarelcitraph noitcnuf;};eixodh nruter{)eixodh(img noitcnuf;};rerednerg nruter{)rerednerg(cthg noitcnuf\\n;\"96x\\\\r36x" ascii

  condition:
    uint16(0) == 0x200a and
    all of them
}