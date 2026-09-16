rule TTP_XOR_MULT_DOSStub_d140 {
  strings:
    $key_d140 = { 85 28 [2] f1 30 [2] b6 32 [2] f1 23 [2] bf 2f [2] b3 25 [2] a4 2e [2] bf 60 [2] 82 }

  condition:
    any of them
}