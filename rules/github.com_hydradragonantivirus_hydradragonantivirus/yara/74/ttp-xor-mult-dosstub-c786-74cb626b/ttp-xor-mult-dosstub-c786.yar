rule TTP_XOR_MULT_DOSStub_c786 {
  strings:
    $key_c786 = { 93 ee [2] e7 f6 [2] a0 f4 [2] e7 e5 [2] a9 e9 [2] a5 e3 [2] b2 e8 [2] a9 a6 [2] 94 }

  condition:
    any of them
}