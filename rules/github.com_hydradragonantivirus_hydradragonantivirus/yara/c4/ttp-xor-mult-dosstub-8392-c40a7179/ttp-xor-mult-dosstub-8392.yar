rule TTP_XOR_MULT_DOSStub_8392 {
  strings:
    $key_8392 = { d7 fa [2] a3 e2 [2] e4 e0 [2] a3 f1 [2] ed fd [2] e1 f7 [2] f6 fc [2] ed b2 [2] d0 }

  condition:
    any of them
}