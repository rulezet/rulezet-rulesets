rule TTP_XOR_MULT_DOSStub_c0d0 {
  strings:
    $key_c0d0 = { 94 b8 [2] e0 a0 [2] a7 a2 [2] e0 b3 [2] ae bf [2] a2 b5 [2] b5 be [2] ae f0 [2] 93 }

  condition:
    any of them
}