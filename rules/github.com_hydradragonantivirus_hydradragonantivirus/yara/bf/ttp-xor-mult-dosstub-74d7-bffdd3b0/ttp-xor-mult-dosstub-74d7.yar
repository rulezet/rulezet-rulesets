rule TTP_XOR_MULT_DOSStub_74d7 {
  strings:
    $key_74d7 = { 20 bf [2] 54 a7 [2] 13 a5 [2] 54 b4 [2] 1a b8 [2] 16 b2 [2] 01 b9 [2] 1a f7 [2] 27 }

  condition:
    any of them
}