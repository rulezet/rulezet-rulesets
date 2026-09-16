rule TTP_XOR_MULT_DOSStub_88a7 {
  strings:
    $key_88a7 = { dc cf [2] a8 d7 [2] ef d5 [2] a8 c4 [2] e6 c8 [2] ea c2 [2] fd c9 [2] e6 87 [2] db }

  condition:
    any of them
}