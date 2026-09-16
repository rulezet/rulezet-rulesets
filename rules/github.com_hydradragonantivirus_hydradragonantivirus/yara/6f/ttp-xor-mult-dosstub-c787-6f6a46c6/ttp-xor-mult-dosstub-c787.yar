rule TTP_XOR_MULT_DOSStub_c787 {
  strings:
    $key_c787 = { 93 ef [2] e7 f7 [2] a0 f5 [2] e7 e4 [2] a9 e8 [2] a5 e2 [2] b2 e9 [2] a9 a7 [2] 94 }

  condition:
    any of them
}