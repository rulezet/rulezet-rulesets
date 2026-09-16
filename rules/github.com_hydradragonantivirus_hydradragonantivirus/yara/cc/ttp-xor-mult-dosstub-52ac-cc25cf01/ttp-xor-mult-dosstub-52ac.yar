rule TTP_XOR_MULT_DOSStub_52ac {
  strings:
    $key_52ac = { 06 c4 [2] 72 dc [2] 35 de [2] 72 cf [2] 3c c3 [2] 30 c9 [2] 27 c2 [2] 3c 8c [2] 01 }

  condition:
    any of them
}