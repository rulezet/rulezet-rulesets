rule TTP_XOR_MULT_DOSStub_69ac {
  strings:
    $key_69ac = { 3d c4 [2] 49 dc [2] 0e de [2] 49 cf [2] 07 c3 [2] 0b c9 [2] 1c c2 [2] 07 8c [2] 3a }

  condition:
    any of them
}