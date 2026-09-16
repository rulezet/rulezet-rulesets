rule sig_20160517_583cc12441bc90a9f09259144395e0fb {
  meta:
    description = "datamaliciousorder - file 20160517_583cc12441bc90a9f09259144395e0fb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7ab299e4dddce82a40f90d23374a1c8c1b3da83afedbc629a720965eec413c43"

  strings:
    $s1 = "var w2akl='vnqif3akfmhsrinltx ogxylql2hwbewffzgods2e3sduipbpr2tpvyszcnyqeaz42frmgllcjhesq=rvksl\\'lwnjmtm4mpqcwgukknop1cbigwmuof" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}