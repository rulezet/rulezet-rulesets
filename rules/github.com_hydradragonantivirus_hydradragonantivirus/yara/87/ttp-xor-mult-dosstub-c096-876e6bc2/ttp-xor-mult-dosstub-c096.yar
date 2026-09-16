rule TTP_XOR_MULT_DOSStub_c096 {
  strings:
    $key_c096 = { 94 fe [2] e0 e6 [2] a7 e4 [2] e0 f5 [2] ae f9 [2] a2 f3 [2] b5 f8 [2] ae b6 [2] 93 }

  condition:
    any of them
}