rule TTP_XOR_MULT_DOSStub_c7b1 {
  strings:
    $key_c7b1 = { 93 d9 [2] e7 c1 [2] a0 c3 [2] e7 d2 [2] a9 de [2] a5 d4 [2] b2 df [2] a9 91 [2] 94 }

  condition:
    any of them
}