rule TTP_XOR_MULT_DOSStub_72ac {
  strings:
    $key_72ac = { 26 c4 [2] 52 dc [2] 15 de [2] 52 cf [2] 1c c3 [2] 10 c9 [2] 07 c2 [2] 1c 8c [2] 21 }

  condition:
    any of them
}