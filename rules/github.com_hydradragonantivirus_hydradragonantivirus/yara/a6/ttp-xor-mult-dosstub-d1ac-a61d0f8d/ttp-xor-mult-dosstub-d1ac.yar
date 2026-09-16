rule TTP_XOR_MULT_DOSStub_d1ac {
  strings:
    $key_d1ac = { 85 c4 [2] f1 dc [2] b6 de [2] f1 cf [2] bf c3 [2] b3 c9 [2] a4 c2 [2] bf 8c [2] 82 }

  condition:
    any of them
}