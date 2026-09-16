rule TTP_XOR_MULT_DOSStub_d146 {
  strings:
    $key_d146 = { 85 2e [2] f1 36 [2] b6 34 [2] f1 25 [2] bf 29 [2] b3 23 [2] a4 28 [2] bf 66 [2] 82 }

  condition:
    any of them
}