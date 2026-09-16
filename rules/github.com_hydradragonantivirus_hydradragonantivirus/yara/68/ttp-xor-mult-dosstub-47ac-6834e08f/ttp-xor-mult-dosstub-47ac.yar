rule TTP_XOR_MULT_DOSStub_47ac {
  strings:
    $key_47ac = { 13 c4 [2] 67 dc [2] 20 de [2] 67 cf [2] 29 c3 [2] 25 c9 [2] 32 c2 [2] 29 8c [2] 14 }

  condition:
    any of them
}