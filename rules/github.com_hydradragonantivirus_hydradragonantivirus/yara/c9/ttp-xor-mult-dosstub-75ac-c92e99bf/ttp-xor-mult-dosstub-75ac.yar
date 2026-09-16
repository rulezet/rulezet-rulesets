rule TTP_XOR_MULT_DOSStub_75ac {
  strings:
    $key_75ac = { 21 c4 [2] 55 dc [2] 12 de [2] 55 cf [2] 1b c3 [2] 17 c9 [2] 00 c2 [2] 1b 8c [2] 26 }

  condition:
    any of them
}