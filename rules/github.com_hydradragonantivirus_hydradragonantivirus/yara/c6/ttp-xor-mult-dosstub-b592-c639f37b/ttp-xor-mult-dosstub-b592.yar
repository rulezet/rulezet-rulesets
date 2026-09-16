rule TTP_XOR_MULT_DOSStub_b592 {
  strings:
    $key_b592 = { e1 fa [2] 95 e2 [2] d2 e0 [2] 95 f1 [2] db fd [2] d7 f7 [2] c0 fc [2] db b2 [2] e6 }

  condition:
    any of them
}