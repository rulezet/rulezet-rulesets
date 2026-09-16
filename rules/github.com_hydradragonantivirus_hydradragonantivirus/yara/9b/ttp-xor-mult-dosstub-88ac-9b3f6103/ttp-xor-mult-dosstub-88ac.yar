rule TTP_XOR_MULT_DOSStub_88ac {
  strings:
    $key_88ac = { dc c4 [2] a8 dc [2] ef de [2] a8 cf [2] e6 c3 [2] ea c9 [2] fd c2 [2] e6 8c [2] db }

  condition:
    any of them
}