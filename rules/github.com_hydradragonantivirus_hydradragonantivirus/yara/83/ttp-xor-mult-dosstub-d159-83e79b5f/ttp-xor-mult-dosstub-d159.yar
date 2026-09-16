rule TTP_XOR_MULT_DOSStub_d159 {
  strings:
    $key_d159 = { 85 31 [2] f1 29 [2] b6 2b [2] f1 3a [2] bf 36 [2] b3 3c [2] a4 37 [2] bf 79 [2] 82 }

  condition:
    any of them
}