rule TTP_XOR_MULT_DOSStub_26d1 {
  strings:
    $key_26d1 = { 72 b9 [2] 06 a1 [2] 41 a3 [2] 06 b2 [2] 48 be [2] 44 b4 [2] 53 bf [2] 48 f1 [2] 75 }

  condition:
    any of them
}