rule TTP_XOR_MULT_DOSStub_d109 {
  strings:
    $key_d109 = { 85 61 [2] f1 79 [2] b6 7b [2] f1 6a [2] bf 66 [2] b3 6c [2] a4 67 [2] bf 29 [2] 82 }

  condition:
    any of them
}