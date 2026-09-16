rule TTP_XOR_MULT_DOSStub_d158 {
  strings:
    $key_d158 = { 85 30 [2] f1 28 [2] b6 2a [2] f1 3b [2] bf 37 [2] b3 3d [2] a4 36 [2] bf 78 [2] 82 }

  condition:
    any of them
}