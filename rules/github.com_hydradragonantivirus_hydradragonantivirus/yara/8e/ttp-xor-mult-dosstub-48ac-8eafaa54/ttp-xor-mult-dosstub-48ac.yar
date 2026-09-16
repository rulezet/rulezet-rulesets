rule TTP_XOR_MULT_DOSStub_48ac {
  strings:
    $key_48ac = { 1c c4 [2] 68 dc [2] 2f de [2] 68 cf [2] 26 c3 [2] 2a c9 [2] 3d c2 [2] 26 8c [2] 1b }

  condition:
    any of them
}