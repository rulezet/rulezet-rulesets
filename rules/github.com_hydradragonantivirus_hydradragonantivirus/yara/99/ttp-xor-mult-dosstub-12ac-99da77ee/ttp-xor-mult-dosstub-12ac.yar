rule TTP_XOR_MULT_DOSStub_12ac {
  strings:
    $key_12ac = { 46 c4 [2] 32 dc [2] 75 de [2] 32 cf [2] 7c c3 [2] 70 c9 [2] 67 c2 [2] 7c 8c [2] 41 }

  condition:
    any of them
}