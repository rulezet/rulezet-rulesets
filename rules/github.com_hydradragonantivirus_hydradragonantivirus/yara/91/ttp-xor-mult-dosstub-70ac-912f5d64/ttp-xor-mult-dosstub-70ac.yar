rule TTP_XOR_MULT_DOSStub_70ac {
  strings:
    $key_70ac = { 24 c4 [2] 50 dc [2] 17 de [2] 50 cf [2] 1e c3 [2] 12 c9 [2] 05 c2 [2] 1e 8c [2] 23 }

  condition:
    any of them
}