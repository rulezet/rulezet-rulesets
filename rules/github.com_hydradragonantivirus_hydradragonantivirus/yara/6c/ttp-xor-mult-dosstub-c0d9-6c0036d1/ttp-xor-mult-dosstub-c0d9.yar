rule TTP_XOR_MULT_DOSStub_c0d9 {
  strings:
    $key_c0d9 = { 94 b1 [2] e0 a9 [2] a7 ab [2] e0 ba [2] ae b6 [2] a2 bc [2] b5 b7 [2] ae f9 [2] 93 }

  condition:
    any of them
}