rule TTP_XOR_MULT_DOSStub_14d6 {
  strings:
    $key_14d6 = { 40 be [2] 34 a6 [2] 73 a4 [2] 34 b5 [2] 7a b9 [2] 76 b3 [2] 61 b8 [2] 7a f6 [2] 47 }

  condition:
    any of them
}