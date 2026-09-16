rule TTP_XOR_MULT_DOSStub_42ac {
  strings:
    $key_42ac = { 16 c4 [2] 62 dc [2] 25 de [2] 62 cf [2] 2c c3 [2] 20 c9 [2] 37 c2 [2] 2c 8c [2] 11 }

  condition:
    any of them
}