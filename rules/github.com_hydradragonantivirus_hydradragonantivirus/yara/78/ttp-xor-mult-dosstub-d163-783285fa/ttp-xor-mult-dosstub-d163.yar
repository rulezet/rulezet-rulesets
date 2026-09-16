rule TTP_XOR_MULT_DOSStub_d163 {
  strings:
    $key_d163 = { 85 0b [2] f1 13 [2] b6 11 [2] f1 00 [2] bf 0c [2] b3 06 [2] a4 0d [2] bf 43 [2] 82 }

  condition:
    any of them
}