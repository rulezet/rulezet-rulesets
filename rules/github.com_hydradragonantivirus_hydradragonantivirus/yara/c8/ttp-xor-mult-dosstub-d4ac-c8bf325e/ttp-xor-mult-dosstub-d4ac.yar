rule TTP_XOR_MULT_DOSStub_d4ac {
  strings:
    $key_d4ac = { 80 c4 [2] f4 dc [2] b3 de [2] f4 cf [2] ba c3 [2] b6 c9 [2] a1 c2 [2] ba 8c [2] 87 }

  condition:
    any of them
}