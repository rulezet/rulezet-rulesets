rule TTP_XOR_MULT_DOSStub_07d6 {
  strings:
    $key_07d6 = { 53 be [2] 27 a6 [2] 60 a4 [2] 27 b5 [2] 69 b9 [2] 65 b3 [2] 72 b8 [2] 69 f6 [2] 54 }

  condition:
    any of them
}