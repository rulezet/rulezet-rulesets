rule TTP_XOR_MULT_DOSStub_07ac {
  strings:
    $key_07ac = { 53 c4 [2] 27 dc [2] 60 de [2] 27 cf [2] 69 c3 [2] 65 c9 [2] 72 c2 [2] 69 8c [2] 54 }

  condition:
    any of them
}