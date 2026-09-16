rule TTP_XOR_MULT_DOSStub_d166 {
  strings:
    $key_d166 = { 85 0e [2] f1 16 [2] b6 14 [2] f1 05 [2] bf 09 [2] b3 03 [2] a4 08 [2] bf 46 [2] 82 }

  condition:
    any of them
}