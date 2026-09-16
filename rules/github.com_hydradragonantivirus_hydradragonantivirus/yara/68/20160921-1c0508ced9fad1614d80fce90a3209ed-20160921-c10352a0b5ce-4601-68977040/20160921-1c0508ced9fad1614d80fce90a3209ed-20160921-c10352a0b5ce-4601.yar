rule _20160921_1c0508ced9fad1614d80fce90a3209ed_20160921_c10352a0b5ce_4601 {
  meta:
    description = "datamaliciousorder - from files 20160921_1c0508ced9fad1614d80fce90a3209ed.js, 20160921_c10352a0b5ce476f023184a502920234.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e27406e32c891781b5403c718c4f32d67f6580cf6f952a30d0c6452ab9775a4c"
    hash2       = "661c8aa3c79751c20d118989114b454234f6dbf4ba9604e917fa5191741d3298"

  strings:
    $s1 = "f000(){return \"GGn\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"BQ" ascii
    $s2 = "),(function f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"OMd\";})(),(function f000(" ascii
    $s3 = "00(){return \"Yi\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"OMd\";})(),(function f000(){return \"Lp\"" ascii
    $s4 = " f000(){return \"OMd\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"MMz\";})(),(function f000(){return \"M" ascii
    $s5 = "return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Yv\";})(),(function f000(){return \"Qj\";})()," ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}