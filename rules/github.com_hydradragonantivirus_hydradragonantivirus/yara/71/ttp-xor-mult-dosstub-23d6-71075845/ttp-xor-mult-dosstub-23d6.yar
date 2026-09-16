rule TTP_XOR_MULT_DOSStub_23d6 {
  strings:
    $key_23d6 = { 77 be [2] 03 a6 [2] 44 a4 [2] 03 b5 [2] 4d b9 [2] 41 b3 [2] 56 b8 [2] 4d f6 [2] 70 }

  condition:
    any of them
}