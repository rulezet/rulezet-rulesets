rule TTP_XOR_MULT_DOSStub_d139 {
  strings:
    $key_d139 = { 85 51 [2] f1 49 [2] b6 4b [2] f1 5a [2] bf 56 [2] b3 5c [2] a4 57 [2] bf 19 [2] 82 }

  condition:
    any of them
}