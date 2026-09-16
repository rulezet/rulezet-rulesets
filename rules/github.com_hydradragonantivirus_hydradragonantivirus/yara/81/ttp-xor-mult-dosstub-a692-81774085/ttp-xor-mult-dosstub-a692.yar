rule TTP_XOR_MULT_DOSStub_a692 {
  strings:
    $key_a692 = { f2 fa [2] 86 e2 [2] c1 e0 [2] 86 f1 [2] c8 fd [2] c4 f7 [2] d3 fc [2] c8 b2 [2] f5 }

  condition:
    any of them
}