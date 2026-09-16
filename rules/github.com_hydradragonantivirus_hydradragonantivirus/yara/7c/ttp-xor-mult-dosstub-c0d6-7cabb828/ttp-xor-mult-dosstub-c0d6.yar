rule TTP_XOR_MULT_DOSStub_c0d6 {
  strings:
    $key_c0d6 = { 94 be [2] e0 a6 [2] a7 a4 [2] e0 b5 [2] ae b9 [2] a2 b3 [2] b5 b8 [2] ae f6 [2] 93 }

  condition:
    any of them
}