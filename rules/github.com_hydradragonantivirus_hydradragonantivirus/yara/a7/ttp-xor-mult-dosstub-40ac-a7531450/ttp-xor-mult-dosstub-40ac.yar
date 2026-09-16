rule TTP_XOR_MULT_DOSStub_40ac {
  strings:
    $key_40ac = { 14 c4 [2] 60 dc [2] 27 de [2] 60 cf [2] 2e c3 [2] 22 c9 [2] 35 c2 [2] 2e 8c [2] 13 }

  condition:
    any of them
}