rule TTP_XOR_MULT_DOSStub_8590 {
  strings:
    $key_8590 = { d1 f8 [2] a5 e0 [2] e2 e2 [2] a5 f3 [2] eb ff [2] e7 f5 [2] f0 fe [2] eb b0 [2] d6 }

  condition:
    any of them
}