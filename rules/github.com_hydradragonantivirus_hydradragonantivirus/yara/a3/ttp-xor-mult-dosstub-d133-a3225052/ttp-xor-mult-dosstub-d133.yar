rule TTP_XOR_MULT_DOSStub_d133 {
  strings:
    $key_d133 = { 85 5b [2] f1 43 [2] b6 41 [2] f1 50 [2] bf 5c [2] b3 56 [2] a4 5d [2] bf 13 [2] 82 }

  condition:
    any of them
}