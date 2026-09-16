rule TTP_XOR_MULT_DOSStub_d145 {
  strings:
    $key_d145 = { 85 2d [2] f1 35 [2] b6 37 [2] f1 26 [2] bf 2a [2] b3 20 [2] a4 2b [2] bf 65 [2] 82 }

  condition:
    any of them
}