rule _20160921_37277908f8111ad292e17a84927fe01d_20160921_d999dcba53f5_1565 {
  meta:
    description = "datamaliciousorder - from files 20160921_37277908f8111ad292e17a84927fe01d.js, 20160921_d999dcba53f56b5a9c1abcc062fbeb80.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cac56e804b2f49b3fcd9bbc13fbdc4deb3a0ef68848e6527c15ab41f1104f286"
    hash2       = "3bf893eeec71a95167368eb58abcbfe36362779b946b3e0d29c9032ec427ebd4"

  strings:
    $s1  = "tion f000(){return \"WIj\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Yi\";})(),(function f000(){return" ascii
    $s2  = "function f000(){return \"KDh\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"OUx\";})(),(function f000(){r" ascii
    $s3  = "{return \"Qz\";})(),(function f000(){return \"OMd\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Nv\";})(" ascii
    $s4  = "GGn\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Mt\";})(),(function" ascii
    $s5  = "000(){return \"Rh\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"HJm" ascii
    $s6  = "(function f000(){return \"SEo\";})(),(function f000(){return \"RVb\";})(),(function f000(){return \"Yi\";})(),(function f000(){r" ascii
    $s7  = "Db\";})(),(function f000(){return \"MMz\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"Mc\";})(),(functio" ascii
    $s8  = "\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"BQb\";})(),(function" ascii
    $s9  = "),(function f000(){return \"Sv\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"KXg\";})(),(function f000(){" ascii
    $s10 = "){return \"Kw\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"BQb\";}" ascii
    $s11 = "0(){return \"Yi\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"GGn\";" ascii
    $s12 = "ion f000(){return \"Go\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"MDb\";})(),(function f000(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}