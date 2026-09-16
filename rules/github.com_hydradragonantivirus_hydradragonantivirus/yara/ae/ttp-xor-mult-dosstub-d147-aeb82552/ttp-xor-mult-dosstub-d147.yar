rule TTP_XOR_MULT_DOSStub_d147 {
  strings:
    $key_d147 = { 85 2f [2] f1 37 [2] b6 35 [2] f1 24 [2] bf 28 [2] b3 22 [2] a4 29 [2] bf 67 [2] 82 }

  condition:
    any of them
}