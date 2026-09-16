rule TTP_XOR_MULT_DOSStub_c7c0 {
  strings:
    $key_c7c0 = { 93 a8 [2] e7 b0 [2] a0 b2 [2] e7 a3 [2] a9 af [2] a5 a5 [2] b2 ae [2] a9 e0 [2] 94 }

  condition:
    any of them
}