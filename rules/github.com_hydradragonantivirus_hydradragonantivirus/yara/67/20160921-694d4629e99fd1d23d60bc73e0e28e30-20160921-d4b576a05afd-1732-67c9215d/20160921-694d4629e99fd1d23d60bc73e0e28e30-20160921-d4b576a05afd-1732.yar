rule _20160921_694d4629e99fd1d23d60bc73e0e28e30_20160921_d4b576a05afd_1732 {
  meta:
    description = "datamaliciousorder - from files 20160921_694d4629e99fd1d23d60bc73e0e28e30.js, 20160921_d4b576a05afdcd9649d02e422feb16d3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "01147c2f2f43df58f5a1b60481a04add7d73eba030abaeed3f9dedb1fd3574e4"
    hash2       = "221c028d5b96ed7d5655800598b47b367ee2d1927826d126b5808db32c9a01f2"

  strings:
    $s1  = "x\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"Na\";})(),(function fuck(){return \"IPu\";})(),(function" ascii
    $s2  = " \"ADy\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"Jh\";})(),(fun" ascii
    $s3  = "ck(){return \"IPu\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"Ik\"" ascii
    $s4  = "n \"DRx\";})(),(function fuck(){return \"MIl\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"ZVi\";})(),(f" ascii
    $s5  = "\"OQr\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"ZVi\";})(),(func" ascii
    $s6  = " \"IPu\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"Cd\";})(),(fun" ascii
    $s7  = "),(function fuck(){return \"CCb\";})(),(function fuck(){return \"Jg\";})(),(function fuck(){return \"RAi\";})(),(function fuck()" ascii
    $s8  = "{return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"ZLd\";}" ascii
    $s9  = "nction fuck(){return \"DRx\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"QTc\";})(),(function fuck(){retu" ascii
    $s10 = "k(){return \"DRx\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"GNm\";" ascii
    $s11 = "function fuck(){return \"MUs\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){r" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}