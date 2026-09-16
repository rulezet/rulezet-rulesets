rule _20160921_1c0508ced9fad1614d80fce90a3209ed_20160921_aa105be6eeb7_3471 {
  meta:
    description = "datamaliciousorder - from files 20160921_1c0508ced9fad1614d80fce90a3209ed.js, 20160921_aa105be6eeb7f536b3fae098f4cc14ed.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e27406e32c891781b5403c718c4f32d67f6580cf6f952a30d0c6452ab9775a4c"
    hash2       = "df7bae330cc77ba04437c13d3843c951b5c3db558d70c922c4f339dfdc29abbd"

  strings:
    $s1 = "\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"EZu\";})(),(function f" ascii
    $s2 = "urn \"Do\";})(),(function f000(){return \"OMd\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(" ascii
    $s3 = "eturn \"WIj\";})(),(function f000(){return \"OMd\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"TKl\";})()" ascii
    $s4 = "unction f000(){return \"OMd\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"TRc\";})(),(function f000(){re" ascii
    $s5 = "n \"OMd\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"Lp\";})(),(fun" ascii
    $s6 = "Ij\";})(),(function f000(){return \"OMd\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"TKl\";})(),(functio" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}