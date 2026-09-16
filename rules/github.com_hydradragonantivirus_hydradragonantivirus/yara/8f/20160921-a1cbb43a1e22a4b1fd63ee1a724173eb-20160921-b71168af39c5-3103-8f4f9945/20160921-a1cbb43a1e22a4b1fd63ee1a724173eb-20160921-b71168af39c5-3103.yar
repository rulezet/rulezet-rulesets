rule _20160921_a1cbb43a1e22a4b1fd63ee1a724173eb_20160921_b71168af39c5_3103 {
  meta:
    description = "datamaliciousorder - from files 20160921_a1cbb43a1e22a4b1fd63ee1a724173eb.js, 20160921_b71168af39c5eec1d403d381eea7ffe1.js, 20160921_da7f7f057c35b886425ec822f654da90.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4154e4928eccd35fa0d42dbefe4a742700d77124216f8b5756b8ef63634071d3"
    hash2       = "c8811edeb74999e8dd226f7fa9d7963ccfc998904ecb9474d036376253dc6fde"
    hash3       = "b6935463e925cb13fc2413b3d7559cf8e9f5072c15dc73075977046a3e27e417"

  strings:
    $s1 = "ction f000(){return \"NYh\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"GGn\";})(),(function f000(){retu" ascii
    $s2 = "function f000(){return \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"NYh\";})(),(function f000(){re" ascii
    $s3 = "rn \"WIj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"Vu\";})(),(fu" ascii
    $s4 = "0(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"Qa\";}" ascii
    $s5 = "){return \"Ut\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Qj\";})" ascii
    $s6 = "ZIi\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})(),(functi" ascii
    $s7 = "tion f000(){return \"Qj\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Qj\";})(),(function f000(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}