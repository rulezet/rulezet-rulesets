rule TTP_XOR_MULT_DOSStub_25ac {
  strings:
    $key_25ac = { 71 c4 [2] 05 dc [2] 42 de [2] 05 cf [2] 4b c3 [2] 47 c9 [2] 50 c2 [2] 4b 8c [2] 76 }

  condition:
    any of them
}