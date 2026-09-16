rule _20160921_18e4d81197d615e3008ec96ea25b7dc4_20160921_cdeac57ac549_4546 {
  meta:
    description = "datamaliciousorder - from files 20160921_18e4d81197d615e3008ec96ea25b7dc4.js, 20160921_cdeac57ac549120611856c7af0c490f6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4b707313cf8ee2fdf903e5516937a17e48e75059c21a08483659705a96da9670"
    hash2       = "53694193718c2cb2f90fada2d6a11f07ab2c3f8451a0f41ae580b87a142e212e"

  strings:
    $s1 = "(){return \"RLk\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Yv\";}" ascii
    $s2 = " \"Yi\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"MMz\";})(),(func" ascii
    $s3 = "){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"Yv\";})" ascii
    $s4 = "tion f000(){return \"Sq\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do\";})(),(function f000(){return " ascii
    $s5 = "n \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"Oh\";})(),(fun" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}