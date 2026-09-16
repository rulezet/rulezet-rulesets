rule TTP_XOR_MULT_DOSStub_21ac {
  strings:
    $key_21ac = { 75 c4 [2] 01 dc [2] 46 de [2] 01 cf [2] 4f c3 [2] 43 c9 [2] 54 c2 [2] 4f 8c [2] 72 }

  condition:
    any of them
}