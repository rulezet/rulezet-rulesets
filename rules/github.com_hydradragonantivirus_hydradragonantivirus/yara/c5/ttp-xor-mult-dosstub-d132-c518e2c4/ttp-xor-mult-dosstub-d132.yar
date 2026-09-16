rule TTP_XOR_MULT_DOSStub_d132 {
  strings:
    $key_d132 = { 85 5a [2] f1 42 [2] b6 40 [2] f1 51 [2] bf 5d [2] b3 57 [2] a4 5c [2] bf 12 [2] 82 }

  condition:
    any of them
}