rule TTP_XOR_MULT_DOSStub_d125 {
  strings:
    $key_d125 = { 85 4d [2] f1 55 [2] b6 57 [2] f1 46 [2] bf 4a [2] b3 40 [2] a4 4b [2] bf 05 [2] 82 }

  condition:
    any of them
}