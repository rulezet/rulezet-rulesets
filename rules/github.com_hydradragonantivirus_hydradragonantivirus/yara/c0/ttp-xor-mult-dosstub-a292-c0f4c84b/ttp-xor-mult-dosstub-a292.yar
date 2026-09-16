rule TTP_XOR_MULT_DOSStub_a292 {
  strings:
    $key_a292 = { f6 fa [2] 82 e2 [2] c5 e0 [2] 82 f1 [2] cc fd [2] c0 f7 [2] d7 fc [2] cc b2 [2] f1 }

  condition:
    any of them
}