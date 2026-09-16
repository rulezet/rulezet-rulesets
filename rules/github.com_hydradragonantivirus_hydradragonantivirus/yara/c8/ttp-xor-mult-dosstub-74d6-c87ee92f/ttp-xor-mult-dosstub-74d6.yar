rule TTP_XOR_MULT_DOSStub_74d6 {
  strings:
    $key_74d6 = { 20 be [2] 54 a6 [2] 13 a4 [2] 54 b5 [2] 1a b9 [2] 16 b3 [2] 01 b8 [2] 1a f6 [2] 27 }

  condition:
    any of them
}