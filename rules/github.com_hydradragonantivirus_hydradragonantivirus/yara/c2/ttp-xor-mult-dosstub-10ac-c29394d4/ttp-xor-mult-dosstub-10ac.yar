rule TTP_XOR_MULT_DOSStub_10ac {
  strings:
    $key_10ac = { 44 c4 [2] 30 dc [2] 77 de [2] 30 cf [2] 7e c3 [2] 72 c9 [2] 65 c2 [2] 7e 8c [2] 43 }

  condition:
    any of them
}