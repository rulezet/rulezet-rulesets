rule TTP_XOR_MULT_DOSStub_41ac {
  strings:
    $key_41ac = { 15 c4 [2] 61 dc [2] 26 de [2] 61 cf [2] 2f c3 [2] 23 c9 [2] 34 c2 [2] 2f 8c [2] 12 }

  condition:
    any of them
}