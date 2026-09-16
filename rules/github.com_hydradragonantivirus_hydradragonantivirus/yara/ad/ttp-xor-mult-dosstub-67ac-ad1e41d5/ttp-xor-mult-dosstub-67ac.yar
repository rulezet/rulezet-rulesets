rule TTP_XOR_MULT_DOSStub_67ac {
  strings:
    $key_67ac = { 33 c4 [2] 47 dc [2] 00 de [2] 47 cf [2] 09 c3 [2] 05 c9 [2] 12 c2 [2] 09 8c [2] 34 }

  condition:
    any of them
}