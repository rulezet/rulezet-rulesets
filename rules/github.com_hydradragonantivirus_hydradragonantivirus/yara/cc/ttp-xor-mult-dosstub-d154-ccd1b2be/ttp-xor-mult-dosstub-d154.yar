rule TTP_XOR_MULT_DOSStub_d154 {
  strings:
    $key_d154 = { 85 3c [2] f1 24 [2] b6 26 [2] f1 37 [2] bf 3b [2] b3 31 [2] a4 3a [2] bf 74 [2] 82 }

  condition:
    any of them
}