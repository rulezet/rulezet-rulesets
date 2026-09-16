rule TTP_XOR_MULT_DOSStub_d112 {
  strings:
    $key_d112 = { 85 7a [2] f1 62 [2] b6 60 [2] f1 71 [2] bf 7d [2] b3 77 [2] a4 7c [2] bf 32 [2] 82 }

  condition:
    any of them
}