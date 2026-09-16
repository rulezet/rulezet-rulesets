rule TTP_XOR_MULT_DOSStub_85c3 {
  strings:
    $key_85c3 = { d1 ab [2] a5 b3 [2] e2 b1 [2] a5 a0 [2] eb ac [2] e7 a6 [2] f0 ad [2] eb e3 [2] d6 }

  condition:
    any of them
}