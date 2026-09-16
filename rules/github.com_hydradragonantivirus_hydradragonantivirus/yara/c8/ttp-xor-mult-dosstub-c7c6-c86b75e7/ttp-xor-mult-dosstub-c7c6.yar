rule TTP_XOR_MULT_DOSStub_c7c6 {
  strings:
    $key_c7c6 = { 93 ae [2] e7 b6 [2] a0 b4 [2] e7 a5 [2] a9 a9 [2] a5 a3 [2] b2 a8 [2] a9 e6 [2] 94 }

  condition:
    any of them
}