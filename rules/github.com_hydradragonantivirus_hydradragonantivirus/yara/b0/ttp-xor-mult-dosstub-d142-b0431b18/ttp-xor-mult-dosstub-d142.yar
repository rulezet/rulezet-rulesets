rule TTP_XOR_MULT_DOSStub_d142 {
  strings:
    $key_d142 = { 85 2a [2] f1 32 [2] b6 30 [2] f1 21 [2] bf 2d [2] b3 27 [2] a4 2c [2] bf 62 [2] 82 }

  condition:
    any of them
}