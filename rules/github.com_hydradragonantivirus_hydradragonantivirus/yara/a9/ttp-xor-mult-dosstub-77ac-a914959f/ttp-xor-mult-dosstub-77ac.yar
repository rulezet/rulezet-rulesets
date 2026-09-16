rule TTP_XOR_MULT_DOSStub_77ac {
  strings:
    $key_77ac = { 23 c4 [2] 57 dc [2] 10 de [2] 57 cf [2] 19 c3 [2] 15 c9 [2] 02 c2 [2] 19 8c [2] 24 }

  condition:
    any of them
}