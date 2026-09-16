rule TTP_XOR_MULT_DOSStub_8192 {
  strings:
    $key_8192 = { d5 fa [2] a1 e2 [2] e6 e0 [2] a1 f1 [2] ef fd [2] e3 f7 [2] f4 fc [2] ef b2 [2] d2 }

  condition:
    any of them
}