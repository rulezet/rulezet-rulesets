rule _20160921_d6dc24b88112bfdeca39a6062c7510f7_20160921_f3a36d70a836_4068 {
  meta:
    description = "datamaliciousorder - from files 20160921_d6dc24b88112bfdeca39a6062c7510f7.js, 20160921_f3a36d70a83646fa6d4f183bc8e1b1c7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b22daaadbd25f5bd920609cbc37e7ea10c4cd99c069220697c4c5db594cffee2"
    hash2       = "331653a2e8936f9d68b3db693057e89f7c2bcfbb22d7e5f8e7dd76dcf11e3ab4"

  strings:
    $s1 = "})(),(function f000(){return \"DYx\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"Oe\";})(),(function f00" ascii
    $s2 = "000(){return \"TKl\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"DIa" ascii
    $s3 = "tion f000(){return \"Ml\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"DYx\";})(),(function f000(){return " ascii
    $s4 = "tion f000(){return \"DNa\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"GGn\";})(),(function f000(){retur" ascii
    $s5 = "{return \"Go\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Yi\";})()," ascii
    $s6 = "{return \"Yi\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"ZFe\";})(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}