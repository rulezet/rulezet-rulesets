rule _20160921_a3beeaf5374452a126fde6e8bd845f1d_20160921_e2594cbf7523_5606 {
  meta:
    description = "datamaliciousorder - from files 20160921_a3beeaf5374452a126fde6e8bd845f1d.js, 20160921_e2594cbf75233509eaea515aa1a7a2f1.js, 20160921_e6569e3fc498e9fab243cf8dcef2ac51.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b85118fedd76dd449fd30cfd693681aa77891d92c19c3fa0e9dd14f034e867bb"
    hash2       = "9bcadd89dbaf0700ab19bcb2d52d99cb9fdc4145fae40ae3eb529de8d9ada04c"
    hash3       = "d08c501a52afbdcde7669d2b9c40865025e38aa75b2aebf8c71433565dbc7010"

  strings:
    $s1 = "ction f000(){return \"TKp\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"KDh\";})(),(function f000(){retu" ascii
    $s2 = "ction f000(){return \"Yv\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"WIj\";})(),(function f000(){return" ascii
    $s3 = "f000(){return \"WIj\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"Y" ascii
    $s4 = "eturn \"NYh\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"MMz\";})()" ascii
    $s5 = "){return \"MMz\";})(),(function f000(){return \"MKa\";})(),(function f000(){return \"Ot\";})(),(function f000(){return \"ZFe\";}" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}