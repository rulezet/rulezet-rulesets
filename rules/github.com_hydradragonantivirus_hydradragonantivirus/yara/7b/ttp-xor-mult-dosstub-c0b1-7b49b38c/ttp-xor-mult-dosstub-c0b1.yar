rule TTP_XOR_MULT_DOSStub_c0b1 {
  strings:
    $key_c0b1 = { 94 d9 [2] e0 c1 [2] a7 c3 [2] e0 d2 [2] ae de [2] a2 d4 [2] b5 df [2] ae 91 [2] 93 }

  condition:
    any of them
}