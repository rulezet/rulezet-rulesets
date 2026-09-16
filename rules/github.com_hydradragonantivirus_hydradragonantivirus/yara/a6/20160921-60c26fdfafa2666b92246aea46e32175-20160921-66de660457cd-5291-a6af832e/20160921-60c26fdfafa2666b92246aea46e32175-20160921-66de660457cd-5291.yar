rule _20160921_60c26fdfafa2666b92246aea46e32175_20160921_66de660457cd_5291 {
  meta:
    description = "datamaliciousorder - from files 20160921_60c26fdfafa2666b92246aea46e32175.js, 20160921_66de660457cd1dcbe458e50b91bafaca.js, 20160921_8ab8e9ec61d829b3b36dc8e0cbc3b477.js, 20160921_dc1d9050026f8e96fefca2306b0b5aba.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e4cfca41d64bbf1a0959643523d4734a108bc3ecf6147c83f60db030586c6f25"
    hash2       = "0c92eafe23596e161cf04cc6206b7e5cac5dafb3ce36772cc5a8a4f0f827211c"
    hash3       = "6302a5443fa0c0309aa33e24b90ed81d05258a2a800cda52321e903fc44e0494"
    hash4       = "c6189a2d5bf1254f55c8d7ad46101d9c32dc62eda1d03b19dddb22f049f8965d"

  strings:
    $s1 = "000(){return \"GGn\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"GGn" ascii
    $s2 = "f000(){return \"Ot\";})(),(function f000(){return \"Ot\";})(),(function f000(){return \"EZu\";})(),(function f000(){return \"Km" ascii
    $s3 = "return \"OUx\";})(),(function f000(){return \"Tb\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"GGn\";})()" ascii
    $s4 = "turn \"Sj\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"QDg\";})(),(" ascii
    $s5 = "on f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Yv\";})(),(function f000(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}