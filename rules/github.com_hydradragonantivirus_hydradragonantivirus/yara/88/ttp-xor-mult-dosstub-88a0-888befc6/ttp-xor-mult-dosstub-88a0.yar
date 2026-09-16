rule TTP_XOR_MULT_DOSStub_88a0 {
  strings:
    $key_88a0 = { dc c8 [2] a8 d0 [2] ef d2 [2] a8 c3 [2] e6 cf [2] ea c5 [2] fd ce [2] e6 80 [2] db }

  condition:
    any of them
}