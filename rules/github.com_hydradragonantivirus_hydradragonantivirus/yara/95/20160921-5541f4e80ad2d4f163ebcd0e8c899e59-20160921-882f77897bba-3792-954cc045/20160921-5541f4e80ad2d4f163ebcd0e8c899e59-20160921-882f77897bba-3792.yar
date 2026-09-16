rule _20160921_5541f4e80ad2d4f163ebcd0e8c899e59_20160921_882f77897bba_3792 {
  meta:
    description = "datamaliciousorder - from files 20160921_5541f4e80ad2d4f163ebcd0e8c899e59.js, 20160921_882f77897bba85afdc56810c29ef4cbb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "615edf37483855ab2b78dd87e38795245913e5fc6efc9bc47d9e698132792739"
    hash2       = "9e1a86c6dc71a5b10659658c07a01bb1541887750ecf88ab56997c7dbc2d180c"

  strings:
    $s1 = "ction f000(){return \"Vu\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Kw\";})(),(function f000(){return " ascii
    $s2 = "rn \"Kw\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Vu\";})(),(fu" ascii
    $s3 = "){return \"Qz\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Vu\";})" ascii
    $s4 = "function f000(){return \"RPt\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Vj\";})(),(function f000(){ret" ascii
    $s5 = "eturn \"RPt\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Zj\";})(),(" ascii
    $s6 = "{return \"Kw\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do\";})()" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}