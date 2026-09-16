rule TTP_XOR_MULT_DOSStub_13ac {
  strings:
    $key_13ac = { 47 c4 [2] 33 dc [2] 74 de [2] 33 cf [2] 7d c3 [2] 71 c9 [2] 66 c2 [2] 7d 8c [2] 40 }

  condition:
    any of them
}