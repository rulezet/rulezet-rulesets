rule TTP_XOR_MULT_DOSStub_d18b {
  strings:
    $key_d18b = { 85 e3 [2] f1 fb [2] b6 f9 [2] f1 e8 [2] bf e4 [2] b3 ee [2] a4 e5 [2] bf ab [2] 82 }

  condition:
    any of them
}