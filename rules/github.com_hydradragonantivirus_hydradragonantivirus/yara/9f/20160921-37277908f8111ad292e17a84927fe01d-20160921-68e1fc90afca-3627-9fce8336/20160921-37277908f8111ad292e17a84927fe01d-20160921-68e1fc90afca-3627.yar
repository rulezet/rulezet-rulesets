rule _20160921_37277908f8111ad292e17a84927fe01d_20160921_68e1fc90afca_3627 {
  meta:
    description = "datamaliciousorder - from files 20160921_37277908f8111ad292e17a84927fe01d.js, 20160921_68e1fc90afca497654d8f771197c2097.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cac56e804b2f49b3fcd9bbc13fbdc4deb3a0ef68848e6527c15ab41f1104f286"
    hash2       = "2dfe35f2d9bfd20a5e4771207c1627566795391c957d7b630cc669d3d8856ffd"

  strings:
    $s1 = "ion f000(){return \"DYx\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"MDb\";})(),(function f000(){return" ascii
    $s2 = "return \"MJq\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"ZIi\";})(" ascii
    $s3 = ";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"Zj\";})(),(function f00" ascii
    $s4 = "ion f000(){return \"Sv\";})(),(function f000(){return \"NYh\";})(),(function f000(){return \"PTs\";})(),(function f000(){return " ascii
    $s5 = "(){return \"Lp\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"NBs\";})(),(function f000(){return \"Qz\";})" ascii
    $s6 = "eturn \"DNa\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}