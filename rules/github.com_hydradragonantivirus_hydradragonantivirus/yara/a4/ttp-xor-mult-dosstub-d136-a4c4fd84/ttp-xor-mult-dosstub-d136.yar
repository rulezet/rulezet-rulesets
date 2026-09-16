rule TTP_XOR_MULT_DOSStub_d136 {
  strings:
    $key_d136 = { 85 5e [2] f1 46 [2] b6 44 [2] f1 55 [2] bf 59 [2] b3 53 [2] a4 58 [2] bf 16 [2] 82 }

  condition:
    any of them
}