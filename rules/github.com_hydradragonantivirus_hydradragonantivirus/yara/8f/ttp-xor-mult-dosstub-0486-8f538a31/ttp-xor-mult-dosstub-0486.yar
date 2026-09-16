rule TTP_XOR_MULT_DOSStub_0486 {
  strings:
    $key_0486 = { 50 ee [2] 24 f6 [2] 63 f4 [2] 24 e5 [2] 6a e9 [2] 66 e3 [2] 71 e8 [2] 6a a6 [2] 57 }

  condition:
    any of them
}