rule TTP_XOR_MULT_DOSStub_74d1 {
  strings:
    $key_74d1 = { 20 b9 [2] 54 a1 [2] 13 a3 [2] 54 b2 [2] 1a be [2] 16 b4 [2] 01 bf [2] 1a f1 [2] 27 }

  condition:
    any of them
}