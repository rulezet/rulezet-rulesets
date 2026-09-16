rule TTP_XOR_MULT_DOSStub_39ac {
  strings:
    $key_39ac = { 6d c4 [2] 19 dc [2] 5e de [2] 19 cf [2] 57 c3 [2] 5b c9 [2] 4c c2 [2] 57 8c [2] 6a }

  condition:
    any of them
}