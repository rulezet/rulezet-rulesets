rule TTP_XOR_MULT_DOSStub_07d1 {
  strings:
    $key_07d1 = { 53 b9 [2] 27 a1 [2] 60 a3 [2] 27 b2 [2] 69 be [2] 65 b4 [2] 72 bf [2] 69 f1 [2] 54 }

  condition:
    any of them
}