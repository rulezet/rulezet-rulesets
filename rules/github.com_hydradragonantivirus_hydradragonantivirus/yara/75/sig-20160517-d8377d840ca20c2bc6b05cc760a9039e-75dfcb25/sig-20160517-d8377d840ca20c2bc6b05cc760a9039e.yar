rule sig_20160517_d8377d840ca20c2bc6b05cc760a9039e {
  meta:
    description = "datamaliciousorder - file 20160517_d8377d840ca20c2bc6b05cc760a9039e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "47b28d7a58e1e638c05ffd6efa76792071820377964168e1f77b5f6e5f4b96c8"

  strings:
    $s1 = "var uvzfr='vgqpneajxf3orfahj2 yruskovtzecmsiek3ebosgbkso4hr3xsv4bjkfxr3hbpvgyflbggpml2dchrrdzmp=oehmh\\'tjqjbtuvvnccaphaznkn1eti" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}