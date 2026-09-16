rule TTP_XOR_MULT_DOSStub_01ac {
  strings:
    $key_01ac = { 55 c4 [2] 21 dc [2] 66 de [2] 21 cf [2] 6f c3 [2] 63 c9 [2] 74 c2 [2] 6f 8c [2] 52 }

  condition:
    any of them
}