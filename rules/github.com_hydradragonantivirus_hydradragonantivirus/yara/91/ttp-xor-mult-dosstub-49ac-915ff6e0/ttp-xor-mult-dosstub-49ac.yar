rule TTP_XOR_MULT_DOSStub_49ac {
  strings:
    $key_49ac = { 1d c4 [2] 69 dc [2] 2e de [2] 69 cf [2] 27 c3 [2] 2b c9 [2] 3c c2 [2] 27 8c [2] 1a }

  condition:
    any of them
}