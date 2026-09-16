rule _20160921_2c5e8ccbd48636e7c625aae6ef954560_20160921_8b9d3c425718_2338 {
  meta:
    description = "datamaliciousorder - from files 20160921_2c5e8ccbd48636e7c625aae6ef954560.js, 20160921_8b9d3c425718975422f8fe0d71119686.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "70244ca5fa124af09b1f94729567c09dbc52c05035ee7d20cbe87d35e1fe63c8"
    hash2       = "523032dc97c061d21e22a215d1568aa470cd8d5f46ddb3bae63dafcde8db3687"

  strings:
    $s1 = "return \"DRx\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"DAa\";})()" ascii
    $s2 = "fuck(){return \"DRx\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"IOs\";})(),(function fuck(){return \"H" ascii
    $s3 = "rn \"Ai\";})(),(function fuck(){return \"FJs\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"IPu\";})(),(f" ascii
    $s4 = ";})(),(function fuck(){return \"Av\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"DRx\";})(),(function fu" ascii
    $s5 = ")(),(function fuck(){return \"Av\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"DRx\";})(),(function fuck(" ascii
    $s6 = "ck(){return \"Vb\";})(),(function fuck(){return \"OPz\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Cd\"" ascii
    $s7 = ",(function fuck(){return \"DRx\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){" ascii
    $s8 = "on fuck(){return \"DRx\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}