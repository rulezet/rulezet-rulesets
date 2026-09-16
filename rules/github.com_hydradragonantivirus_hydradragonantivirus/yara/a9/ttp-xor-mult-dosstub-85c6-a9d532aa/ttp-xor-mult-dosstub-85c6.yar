rule TTP_XOR_MULT_DOSStub_85c6 {
  strings:
    $key_85c6 = { d1 ae [2] a5 b6 [2] e2 b4 [2] a5 a5 [2] eb a9 [2] e7 a3 [2] f0 a8 [2] eb e6 [2] d6 }

  condition:
    any of them
}