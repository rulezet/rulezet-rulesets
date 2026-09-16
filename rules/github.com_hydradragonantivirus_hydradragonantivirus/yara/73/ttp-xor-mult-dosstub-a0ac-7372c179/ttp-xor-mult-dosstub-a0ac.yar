rule TTP_XOR_MULT_DOSStub_a0ac {
  strings:
    $key_a0ac = { f4 c4 [2] 80 dc [2] c7 de [2] 80 cf [2] ce c3 [2] c2 c9 [2] d5 c2 [2] ce 8c [2] f3 }

  condition:
    any of them
}