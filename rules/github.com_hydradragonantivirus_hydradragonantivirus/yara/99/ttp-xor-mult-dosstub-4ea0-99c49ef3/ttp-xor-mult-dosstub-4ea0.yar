rule TTP_XOR_MULT_DOSStub_4ea0 {
  strings:
    $key_4ea0 = { 1a c8 [2] 6e d0 [2] 29 d2 [2] 6e c3 [2] 20 cf [2] 2c c5 [2] 3b ce [2] 20 80 [2] 1d }

  condition:
    any of them
}