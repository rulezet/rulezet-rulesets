rule TTP_XOR_MULT_DOSStub_46d6 {
  strings:
    $key_46d6 = { 12 be [2] 66 a6 [2] 21 a4 [2] 66 b5 [2] 28 b9 [2] 24 b3 [2] 33 b8 [2] 28 f6 [2] 15 }

  condition:
    any of them
}