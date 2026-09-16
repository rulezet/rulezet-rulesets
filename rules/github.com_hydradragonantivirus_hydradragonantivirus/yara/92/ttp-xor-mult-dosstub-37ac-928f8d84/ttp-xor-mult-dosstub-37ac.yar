rule TTP_XOR_MULT_DOSStub_37ac {
  strings:
    $key_37ac = { 63 c4 [2] 17 dc [2] 50 de [2] 17 cf [2] 59 c3 [2] 55 c9 [2] 42 c2 [2] 59 8c [2] 64 }

  condition:
    any of them
}