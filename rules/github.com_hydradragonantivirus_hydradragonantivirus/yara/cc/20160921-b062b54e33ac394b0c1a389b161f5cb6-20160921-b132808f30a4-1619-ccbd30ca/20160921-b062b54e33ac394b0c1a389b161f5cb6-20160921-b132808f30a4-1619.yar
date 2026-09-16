rule _20160921_b062b54e33ac394b0c1a389b161f5cb6_20160921_b132808f30a4_1619 {
  meta:
    description = "datamaliciousorder - from files 20160921_b062b54e33ac394b0c1a389b161f5cb6.js, 20160921_b132808f30a4f3b5c484e9734dc93fcc.js, 20160921_e1c974d7750547ace34afdda5a06de15.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5d0516ba7ba35ed307fd316146755f07fe542904a37fc2e0bb6a28a59cb06139"
    hash2       = "03f070dd06dae48f7c253ddc9a238e441aaac22f9de6e238ba5d3ffa0b9220b4"
    hash3       = "bed4e8c71e09f1ca8c800564bc43d4e103353ec558d1f0869c85d3e8f8c43b01"

  strings:
    $s1  = "ZIi\";})(),(function f000(){return \"NBs\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"DIa\";})(),(functi" ascii
    $s2  = "tion f000(){return \"WIj\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"Sj\";})(),(function f000(){return " ascii
    $s3  = "ion f000(){return \"MKa\";})(),(function f000(){return \"MMz\";})(),(function f000(){return \"MKa\";})()];" fullword ascii
    $s4  = ")(),(function f000(){return \"KXg\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Sj\";})(),(function f000" ascii
    $s5  = "000(){return \"GGn\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"Mc\";})(),(function f000(){return \"Do" ascii
    $s6  = " f000(){return \"Br\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Zj" ascii
    $s7  = "(){return \"GGn\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"Mt\";}" ascii
    $s8  = "{return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"RLk\";})" ascii
    $s9  = "{return \"Ot\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"KXg\";})" ascii
    $s10 = "tion f000(){return \"TKp\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"DNa\";})(),(function f000(){retur" ascii
    $s11 = "){return \"GGn\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Zj\";}" ascii
    $s12 = "\"Um\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(funct" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}