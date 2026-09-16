rule TTP_XOR_MULT_DOSStub_88a4 {
  strings:
    $key_88a4 = { dc cc [2] a8 d4 [2] ef d6 [2] a8 c7 [2] e6 cb [2] ea c1 [2] fd ca [2] e6 84 [2] db }

  condition:
    any of them
}