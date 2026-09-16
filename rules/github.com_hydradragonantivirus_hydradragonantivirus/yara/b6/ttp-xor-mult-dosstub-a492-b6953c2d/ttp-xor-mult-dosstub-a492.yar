rule TTP_XOR_MULT_DOSStub_a492 {
  strings:
    $key_a492 = { f0 fa [2] 84 e2 [2] c3 e0 [2] 84 f1 [2] ca fd [2] c6 f7 [2] d1 fc [2] ca b2 [2] f7 }

  condition:
    any of them
}