rule TTP_XOR_MULT_DOSStub_c0d4 {
  strings:
    $key_c0d4 = { 94 bc [2] e0 a4 [2] a7 a6 [2] e0 b7 [2] ae bb [2] a2 b1 [2] b5 ba [2] ae f4 [2] 93 }

  condition:
    any of them
}