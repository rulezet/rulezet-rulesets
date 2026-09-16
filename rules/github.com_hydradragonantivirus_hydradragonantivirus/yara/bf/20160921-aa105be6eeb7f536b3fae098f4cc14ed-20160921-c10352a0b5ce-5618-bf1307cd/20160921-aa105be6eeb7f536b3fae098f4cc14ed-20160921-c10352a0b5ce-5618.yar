rule _20160921_aa105be6eeb7f536b3fae098f4cc14ed_20160921_c10352a0b5ce_5618 {
  meta:
    description = "datamaliciousorder - from files 20160921_aa105be6eeb7f536b3fae098f4cc14ed.js, 20160921_c10352a0b5ce476f023184a502920234.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "df7bae330cc77ba04437c13d3843c951b5c3db558d70c922c4f339dfdc29abbd"
    hash2       = "661c8aa3c79751c20d118989114b454234f6dbf4ba9604e917fa5191741d3298"

  strings:
    $s1 = "n \"EZu\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"OMd\";})(),(fu" ascii
    $s2 = "rn \"Oh\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Do\";})(),(func" ascii
    $s3 = "urn \"XTn\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"MMz\";})(),(" ascii
    $s4 = "ction f000(){return \"GGn\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"Qa\";})(),(function f000(){retur" ascii
    $s5 = "){return \"Vj\";})(),(function f000(){return \"SGs\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";}" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}