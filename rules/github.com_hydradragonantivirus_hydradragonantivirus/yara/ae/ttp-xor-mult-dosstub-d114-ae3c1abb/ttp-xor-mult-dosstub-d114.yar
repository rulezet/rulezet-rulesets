rule TTP_XOR_MULT_DOSStub_d114 {
  strings:
    $key_d114 = { 85 7c [2] f1 64 [2] b6 66 [2] f1 77 [2] bf 7b [2] b3 71 [2] a4 7a [2] bf 34 [2] 82 }

  condition:
    any of them
}