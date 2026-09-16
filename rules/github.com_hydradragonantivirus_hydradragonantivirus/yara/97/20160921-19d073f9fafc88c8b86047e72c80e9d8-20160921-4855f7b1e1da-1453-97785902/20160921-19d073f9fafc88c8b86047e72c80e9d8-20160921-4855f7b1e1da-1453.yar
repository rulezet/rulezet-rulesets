rule _20160921_19d073f9fafc88c8b86047e72c80e9d8_20160921_4855f7b1e1da_1453 {
  meta:
    description = "datamaliciousorder - from files 20160921_19d073f9fafc88c8b86047e72c80e9d8.js, 20160921_4855f7b1e1da9c1c5863fa798f27645a.js, 20160922_b9c8ae1e2648708b7b599ba2ac6333c1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9b03e3cbdce0a3374d427a6b76ef3eb59bc90337947054be78218aab4aa3a5f9"
    hash2       = "3c9b29105af371fead56301baf1fdec90bfe0a8b339dbda43258a67443183fcc"
    hash3       = "e2b244eea80e558d4ae468572be8ba3fade8163b0f8751b10ba6ca2263421085"

  strings:
    $s1  = "n \"Qj\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Qz\";})(),(fun" ascii
    $s2  = "ction f000(){return \"Ot\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"OUx\";})(),(function f000(){retur" ascii
    $s3  = "\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"MMz\";})(),(function" ascii
    $s4  = "00(){return \"KXg\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"Qj\";" ascii
    $s5  = "(){return \"QDg\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"TKp\";}" ascii
    $s6  = "Xg\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Do\";})(),(function" ascii
    $s7  = "ction f000(){return \"IPu\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"OMd\";})(),(function f000(){retur" ascii
    $s8  = "tion f000(){return \"TKl\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"TKl\";})(),(function f000(){return" ascii
    $s9  = "n \"Ot\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Mu\";})(),(fun" ascii
    $s10 = "ction f000(){return \"TKl\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"GGn\";})(),(function f000(){retur" ascii
    $s11 = "{return \"RPt\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"Wh\";})(),(function f000(){return \"QDg\";})" ascii
    $s12 = "0(){return \"Wh\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"KXg\";}" ascii
    $s13 = "tion f000(){return \"Yi\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"RPt\";})(),(function f000(){return" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}