rule TTP_XOR_MULT_DOSStub_41d6 {
  strings:
    $key_41d6 = { 15 be [2] 61 a6 [2] 26 a4 [2] 61 b5 [2] 2f b9 [2] 23 b3 [2] 34 b8 [2] 2f f6 [2] 12 }

  condition:
    any of them
}