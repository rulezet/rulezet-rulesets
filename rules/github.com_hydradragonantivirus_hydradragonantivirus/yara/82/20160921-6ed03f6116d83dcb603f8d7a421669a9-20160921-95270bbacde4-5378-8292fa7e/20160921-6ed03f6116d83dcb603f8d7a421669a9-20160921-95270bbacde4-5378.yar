rule _20160921_6ed03f6116d83dcb603f8d7a421669a9_20160921_95270bbacde4_5378 {
  meta:
    description = "datamaliciousorder - from files 20160921_6ed03f6116d83dcb603f8d7a421669a9.js, 20160921_95270bbacde4afcb3c799d7a0643809d.js, 20160921_a65ac281dbfddbf6dbe63a0288de8c70.js, 20160921_b15ce64784b080eff109e1bd1b00ebf6.js, 20160921_ebd0ee36b6a55e4cbf431d8fa9a2aea3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7f10930e3c0bd956023b78dabf743464a690cb292b06d107d010614acff421c1"
    hash2       = "6cab57b5e35c3714b482592a77f0edbdc9fedb8c6e508d57b8cf63dfd719f5db"
    hash3       = "5498e9d2bd6a9339a0b2314825151361bd8dd59a555d034973bbcac8e2cb195a"
    hash4       = "e78e24f62fb93be4551c02ce2a2a27421a39d4a9d5c77d37c7518adf9e53ce65"
    hash5       = "f2f666db493211ee6edb824e429f601fccdbf25cd3cc08bc16ad31fdf23c4636"

  strings:
    $s1 = "o\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Lo\";})(),(function " ascii
    $s2 = "on f000(){return \"OUx\";})(),(function f000(){return \"Mu\";})(),(function f000(){return \"TKl\";})(),(function f000(){return " ascii
    $s3 = "\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Do\";})(),(function f" ascii
    $s4 = ";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"Br\";})(),(function f00" ascii
    $s5 = "n \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Yi\";})(),(fu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}