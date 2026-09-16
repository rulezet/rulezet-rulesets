rule TTP_XOR_MULT_DOSStub_d174 {
  strings:
    $key_d174 = { 85 1c [2] f1 04 [2] b6 06 [2] f1 17 [2] bf 1b [2] b3 11 [2] a4 1a [2] bf 54 [2] 82 }

  condition:
    any of them
}