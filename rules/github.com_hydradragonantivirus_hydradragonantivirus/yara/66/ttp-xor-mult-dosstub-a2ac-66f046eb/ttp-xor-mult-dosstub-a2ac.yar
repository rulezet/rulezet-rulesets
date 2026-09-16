rule TTP_XOR_MULT_DOSStub_a2ac {
  strings:
    $key_a2ac = { f6 c4 [2] 82 dc [2] c5 de [2] 82 cf [2] cc c3 [2] c0 c9 [2] d7 c2 [2] cc 8c [2] f1 }

  condition:
    any of them
}