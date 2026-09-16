rule TTP_XOR_MULT_DOSStub_d187 {
  strings:
    $key_d187 = { 85 ef [2] f1 f7 [2] b6 f5 [2] f1 e4 [2] bf e8 [2] b3 e2 [2] a4 e9 [2] bf a7 [2] 82 }

  condition:
    any of them
}