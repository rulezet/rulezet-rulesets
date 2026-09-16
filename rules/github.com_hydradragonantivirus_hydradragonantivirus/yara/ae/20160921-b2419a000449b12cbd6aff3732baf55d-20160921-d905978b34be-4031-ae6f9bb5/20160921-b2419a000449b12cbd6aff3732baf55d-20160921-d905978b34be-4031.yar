rule _20160921_b2419a000449b12cbd6aff3732baf55d_20160921_d905978b34be_4031 {
  meta:
    description = "datamaliciousorder - from files 20160921_b2419a000449b12cbd6aff3732baf55d.js, 20160921_d905978b34bea5948e843dd7ecb9dc6e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ea7b5520c177b4adf74565706c3c8ed38eed94f30b6927b0ceb647f7f768a2b5"
    hash2       = "8110e9072a75f1960f23243cc11d3c233a350d63360d8006cad608a2fb81e0b3"

  strings:
    $s1 = "fuck(){return \"Xg\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"Bz" ascii
    $s2 = "urn \"ILp\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"Bz\";})(),(function fuck(){return \"ILp\";})(),(f" ascii
    $s3 = "z\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"FJs\";})(),(functio" ascii
    $s4 = "a\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"AUx\";})(),(function " ascii
    $s5 = " \"Jo\";})(),(function fuck(){return \"FJs\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"Dc\";})(),(funct" ascii
    $s6 = "(){return \"ZVi\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"XCr\";}" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}