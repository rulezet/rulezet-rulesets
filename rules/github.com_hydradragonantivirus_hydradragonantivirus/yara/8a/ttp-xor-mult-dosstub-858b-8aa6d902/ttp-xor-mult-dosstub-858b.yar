rule TTP_XOR_MULT_DOSStub_858b {
  strings:
    $key_858b = { d1 e3 [2] a5 fb [2] e2 f9 [2] a5 e8 [2] eb e4 [2] e7 ee [2] f0 e5 [2] eb ab [2] d6 }

  condition:
    any of them
}