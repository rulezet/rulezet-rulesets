rule TTP_XOR_MULT_DOSStub_c0d2 {
  strings:
    $key_c0d2 = { 94 ba [2] e0 a2 [2] a7 a0 [2] e0 b1 [2] ae bd [2] a2 b7 [2] b5 bc [2] ae f2 [2] 93 }

  condition:
    any of them
}