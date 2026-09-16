rule TTP_XOR_MULT_DOSStub_d1f0 {
  strings:
    $key_d1f0 = { 85 98 [2] f1 80 [2] b6 82 [2] f1 93 [2] bf 9f [2] b3 95 [2] a4 9e [2] bf d0 [2] 82 }

  condition:
    any of them
}