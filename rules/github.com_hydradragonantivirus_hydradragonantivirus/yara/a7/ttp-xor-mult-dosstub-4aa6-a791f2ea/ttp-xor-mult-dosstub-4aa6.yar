rule TTP_XOR_MULT_DOSStub_4aa6 {
  strings:
    $key_4aa6 = { 1e ce [2] 6a d6 [2] 2d d4 [2] 6a c5 [2] 24 c9 [2] 28 c3 [2] 3f c8 [2] 24 86 [2] 19 }

  condition:
    any of them
}