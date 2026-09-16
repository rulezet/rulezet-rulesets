rule TTP_XOR_MULT_DOSStub_d131 {
  strings:
    $key_d131 = { 85 59 [2] f1 41 [2] b6 43 [2] f1 52 [2] bf 5e [2] b3 54 [2] a4 5f [2] bf 11 [2] 82 }

  condition:
    any of them
}