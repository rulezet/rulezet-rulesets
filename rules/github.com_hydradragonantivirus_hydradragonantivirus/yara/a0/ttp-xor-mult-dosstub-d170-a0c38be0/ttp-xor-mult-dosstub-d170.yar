rule TTP_XOR_MULT_DOSStub_d170 {
  strings:
    $key_d170 = { 85 18 [2] f1 00 [2] b6 02 [2] f1 13 [2] bf 1f [2] b3 15 [2] a4 1e [2] bf 50 [2] 82 }

  condition:
    any of them
}