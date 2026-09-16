rule sig_20160525_a1f930ccb59d6271068d48f4b12c0c17 {
  meta:
    description = "datamaliciousorder - file 20160525_a1f930ccb59d6271068d48f4b12c0c17.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7c28060dead9d8fead316feb94200b9de96c9d57ff0de47c031ccae7421205e2"

  strings:
    $s1 = "keppelt rav\\n;)4(]\"tAra\"+\"86x\\\\\"+\"c\"[suidarelcitrapt = ecapsetihwxelft rav;\"em4lbQ\" = suidarelcitrapt rav\\n;\"07x" ascii
    $s2 = "neti rav\\n;\"/%05x\\\\M\" = ssorcai rav\\n;\"G14x\\\\E\" = tsilslianbmuhtoi rav\\n;\"a7x\\\\R\" = cthi rav\\n;\"jk96x\\\\o\" = " ascii

  condition:
    uint16(0) == 0x200a and
    all of them
}