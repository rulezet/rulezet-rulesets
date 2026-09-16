rule TTP_XOR_MULT_DOSStub_d1f8 {
  strings:
    $key_d1f8 = { 85 90 [2] f1 88 [2] b6 8a [2] f1 9b [2] bf 97 [2] b3 9d [2] a4 96 [2] bf d8 [2] 82 }

  condition:
    any of them
}