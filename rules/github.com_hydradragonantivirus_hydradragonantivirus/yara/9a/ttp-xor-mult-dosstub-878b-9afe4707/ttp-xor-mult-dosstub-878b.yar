rule TTP_XOR_MULT_DOSStub_878b {
  strings:
    $key_878b = { d3 e3 [2] a7 fb [2] e0 f9 [2] a7 e8 [2] e9 e4 [2] e5 ee [2] f2 e5 [2] e9 ab [2] d4 }

  condition:
    any of them
}