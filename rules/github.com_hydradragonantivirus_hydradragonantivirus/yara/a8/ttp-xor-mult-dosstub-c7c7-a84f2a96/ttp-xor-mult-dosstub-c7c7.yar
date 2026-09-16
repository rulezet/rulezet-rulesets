rule TTP_XOR_MULT_DOSStub_c7c7 {
  strings:
    $key_c7c7 = { 93 af [2] e7 b7 [2] a0 b5 [2] e7 a4 [2] a9 a8 [2] a5 a2 [2] b2 a9 [2] a9 e7 [2] 94 }

  condition:
    any of them
}