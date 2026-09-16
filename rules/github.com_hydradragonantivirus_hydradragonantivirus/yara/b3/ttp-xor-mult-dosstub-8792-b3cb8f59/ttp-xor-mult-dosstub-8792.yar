rule TTP_XOR_MULT_DOSStub_8792 {
  strings:
    $key_8792 = { d3 fa [2] a7 e2 [2] e0 e0 [2] a7 f1 [2] e9 fd [2] e5 f7 [2] f2 fc [2] e9 b2 [2] d4 }

  condition:
    any of them
}