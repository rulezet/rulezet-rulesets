rule TTP_XOR_MULT_DOSStub_d1f5 {
  strings:
    $key_d1f5 = { 85 9d [2] f1 85 [2] b6 87 [2] f1 96 [2] bf 9a [2] b3 90 [2] a4 9b [2] bf d5 [2] 82 }

  condition:
    any of them
}