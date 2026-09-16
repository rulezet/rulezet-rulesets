rule _20160921_37277908f8111ad292e17a84927fe01d_20160921_8b27f7688489_1475 {
  meta:
    description = "datamaliciousorder - from files 20160921_37277908f8111ad292e17a84927fe01d.js, 20160921_8b27f7688489936aa1cc7fded52f4a64.js, 20160921_d57bd7101328f2bbf1f061a7dab83490.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cac56e804b2f49b3fcd9bbc13fbdc4deb3a0ef68848e6527c15ab41f1104f286"
    hash2       = "dbf2fa1deb81fd17a55e884848d77b2d3c5d766fed0005f738840703aa8a9dda"
    hash3       = "fa72df41c05c5483fee755296c5d2da37c5e14a015c2aac82e7d9ad428cc2376"

  strings:
    $s1  = ";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"DNa\";})(),(function f0" ascii
    $s2  = " f000(){return \"ZIi\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"" ascii
    $s3  = "n f000(){return \"EZu\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"QDg\";})(),(function f000(){return " ascii
    $s4  = " f000(){return \"GGn\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"NYh\";})(),(function f000(){return \"P" ascii
    $s5  = "(function f000(){return \"PTs\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Zj\";})(),(function f000(){r" ascii
    $s6  = " f000(){return \"SGs\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"M" ascii
    $s7  = " \"DNa\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(fu" ascii
    $s8  = "00(){return \"WIj\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"DNa" ascii
    $s9  = ")(),(function f000(){return \"ZFe\";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"Iq\";})(),(function f000" ascii
    $s10 = ")(),(function f000(){return \"MJq\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"HJm\";})(),(function f00" ascii
    $s11 = "turn \"Sv\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"MDb\";})(),(" ascii
    $s12 = "rn \"YTp\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(" ascii
    $s13 = "})(),(function f000(){return \"Yi\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"Zj\";})(),(function f000" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}