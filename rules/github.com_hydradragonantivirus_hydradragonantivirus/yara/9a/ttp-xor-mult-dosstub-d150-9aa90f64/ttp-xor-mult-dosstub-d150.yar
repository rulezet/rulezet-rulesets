rule TTP_XOR_MULT_DOSStub_d150 {
  strings:
    $key_d150 = { 85 38 [2] f1 20 [2] b6 22 [2] f1 33 [2] bf 3f [2] b3 35 [2] a4 3e [2] bf 70 [2] 82 }

  condition:
    any of them
}