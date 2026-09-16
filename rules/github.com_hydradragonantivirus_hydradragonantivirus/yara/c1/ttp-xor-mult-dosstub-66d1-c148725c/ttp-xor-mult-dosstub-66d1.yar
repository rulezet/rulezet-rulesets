rule TTP_XOR_MULT_DOSStub_66d1 {
  strings:
    $key_66d1 = { 32 b9 [2] 46 a1 [2] 01 a3 [2] 46 b2 [2] 08 be [2] 04 b4 [2] 13 bf [2] 08 f1 [2] 35 }

  condition:
    any of them
}