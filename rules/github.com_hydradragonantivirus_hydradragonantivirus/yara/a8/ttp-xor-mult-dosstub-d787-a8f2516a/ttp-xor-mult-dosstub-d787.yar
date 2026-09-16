rule TTP_XOR_MULT_DOSStub_d787 {
  strings:
    $key_d787 = { 83 ef [2] f7 f7 [2] b0 f5 [2] f7 e4 [2] b9 e8 [2] b5 e2 [2] a2 e9 [2] b9 a7 [2] 84 }

  condition:
    any of them
}