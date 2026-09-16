rule TTP_XOR_MULT_DOSStub_d186 {
  strings:
    $key_d186 = { 85 ee [2] f1 f6 [2] b6 f4 [2] f1 e5 [2] bf e9 [2] b3 e3 [2] a4 e8 [2] bf a6 [2] 82 }

  condition:
    any of them
}