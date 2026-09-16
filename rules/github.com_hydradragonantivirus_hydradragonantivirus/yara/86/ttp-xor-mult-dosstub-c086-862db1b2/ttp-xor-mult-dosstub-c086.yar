rule TTP_XOR_MULT_DOSStub_c086 {
  strings:
    $key_c086 = { 94 ee [2] e0 f6 [2] a7 f4 [2] e0 e5 [2] ae e9 [2] a2 e3 [2] b5 e8 [2] ae a6 [2] 93 }

  condition:
    any of them
}