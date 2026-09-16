rule sig_20160517_270e58751e69b0bbd4f483fb9948b6f4 {
  meta:
    description = "datamaliciousorder - file 20160517_270e58751e69b0bbd4f483fb9948b6f4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3a4eb4f1eec5ac127f32e37e293f42aa98493d0edae805a7da251587bc187650"

  strings:
    $s1 = "var y2g3='vcxgnmapzoivraz1rt egxyqjoy2fzhrbbggtund1brz4aimgizl1rcs12dz2xixtrvggw3q1msekt=ldxop\\'jopzotqfpimcr4ymxnzjenlibueeefe" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}