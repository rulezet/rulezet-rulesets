rule TTP_XOR_MULT_DOSStub_d108 {
  strings:
    $key_d108 = { 85 60 [2] f1 78 [2] b6 7a [2] f1 6b [2] bf 67 [2] b3 6d [2] a4 66 [2] bf 28 [2] 82 }

  condition:
    any of them
}