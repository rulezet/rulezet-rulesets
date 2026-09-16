rule TTP_XOR_MULT_DOSStub_56ac {
  strings:
    $key_56ac = { 02 c4 [2] 76 dc [2] 31 de [2] 76 cf [2] 38 c3 [2] 34 c9 [2] 23 c2 [2] 38 8c [2] 05 }

  condition:
    any of them
}