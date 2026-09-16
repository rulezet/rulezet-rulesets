rule sig_20160525_ff9315c0ca521a157be5a0da1801d860 {
  meta:
    description = "datamaliciousorder - file 20160525_ff9315c0ca521a157be5a0da1801d860.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "13c9d3a90145729f2b8fc7fd63026f614f6b91e0aeecc52a4fda90b289f9c5a5"

  strings:
    $s1 = "modnarb+ecapsetihwxelfb+keppelb[ = ctha rav\\n\\n;\"734\" = mb rav\\n;2041 + 0041- = deerda rav\\n;2 = tsilslianbmuhtoa rav\\n;1" ascii
    $s2 = "\"86x\\\\\"+\"c\"[gedotdarh = cthh rav;\"1ocR0\" = gedotdarh rav\\n;\"85x\\\\35x\\\\M\" = eixodi rav\\n;\".23x\\\\LM\" = gsmi ra" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}