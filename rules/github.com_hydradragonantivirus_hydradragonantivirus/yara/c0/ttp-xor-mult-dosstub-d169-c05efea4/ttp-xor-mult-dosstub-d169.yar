rule TTP_XOR_MULT_DOSStub_d169 {
  strings:
    $key_d169 = { 85 01 [2] f1 19 [2] b6 1b [2] f1 0a [2] bf 06 [2] b3 0c [2] a4 07 [2] bf 49 [2] 82 }

  condition:
    any of them
}