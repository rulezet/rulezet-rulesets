rule TTP_XOR_MULT_DOSStub_d181 {
  strings:
    $key_d181 = { 85 e9 [2] f1 f1 [2] b6 f3 [2] f1 e2 [2] bf ee [2] b3 e4 [2] a4 ef [2] bf a1 [2] 82 }

  condition:
    any of them
}