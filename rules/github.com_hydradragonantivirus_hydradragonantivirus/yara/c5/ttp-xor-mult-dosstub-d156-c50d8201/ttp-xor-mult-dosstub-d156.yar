rule TTP_XOR_MULT_DOSStub_d156 {
  strings:
    $key_d156 = { 85 3e [2] f1 26 [2] b6 24 [2] f1 35 [2] bf 39 [2] b3 33 [2] a4 38 [2] bf 76 [2] 82 }

  condition:
    any of them
}