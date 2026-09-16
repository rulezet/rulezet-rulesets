rule TTP_XOR_MULT_DOSStub_d151 {
  strings:
    $key_d151 = { 85 39 [2] f1 21 [2] b6 23 [2] f1 32 [2] bf 3e [2] b3 34 [2] a4 3f [2] bf 71 [2] 82 }

  condition:
    any of them
}