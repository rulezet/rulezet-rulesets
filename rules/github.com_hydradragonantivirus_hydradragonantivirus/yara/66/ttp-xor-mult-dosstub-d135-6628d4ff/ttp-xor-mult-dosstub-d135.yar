rule TTP_XOR_MULT_DOSStub_d135 {
  strings:
    $key_d135 = { 85 5d [2] f1 45 [2] b6 47 [2] f1 56 [2] bf 5a [2] b3 50 [2] a4 5b [2] bf 15 [2] 82 }

  condition:
    any of them
}