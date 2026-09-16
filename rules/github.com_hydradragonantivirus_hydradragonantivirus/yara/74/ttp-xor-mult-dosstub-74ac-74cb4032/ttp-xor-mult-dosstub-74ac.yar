rule TTP_XOR_MULT_DOSStub_74ac {
  strings:
    $key_74ac = { 20 c4 [2] 54 dc [2] 13 de [2] 54 cf [2] 1a c3 [2] 16 c9 [2] 01 c2 [2] 1a 8c [2] 27 }

  condition:
    any of them
}