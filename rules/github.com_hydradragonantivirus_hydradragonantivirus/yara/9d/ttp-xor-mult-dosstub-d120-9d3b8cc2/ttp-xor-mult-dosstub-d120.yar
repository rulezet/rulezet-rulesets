rule TTP_XOR_MULT_DOSStub_d120 {
  strings:
    $key_d120 = { 85 48 [2] f1 50 [2] b6 52 [2] f1 43 [2] bf 4f [2] b3 45 [2] a4 4e [2] bf 00 [2] 82 }

  condition:
    any of them
}