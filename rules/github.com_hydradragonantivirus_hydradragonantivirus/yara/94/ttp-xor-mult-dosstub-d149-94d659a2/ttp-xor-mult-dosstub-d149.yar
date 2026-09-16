rule TTP_XOR_MULT_DOSStub_d149 {
  strings:
    $key_d149 = { 85 21 [2] f1 39 [2] b6 3b [2] f1 2a [2] bf 26 [2] b3 2c [2] a4 27 [2] bf 69 [2] 82 }

  condition:
    any of them
}