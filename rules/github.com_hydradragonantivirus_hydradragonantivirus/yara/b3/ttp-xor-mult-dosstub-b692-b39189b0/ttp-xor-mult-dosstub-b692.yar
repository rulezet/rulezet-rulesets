rule TTP_XOR_MULT_DOSStub_b692 {
  strings:
    $key_b692 = { e2 fa [2] 96 e2 [2] d1 e0 [2] 96 f1 [2] d8 fd [2] d4 f7 [2] c3 fc [2] d8 b2 [2] e5 }

  condition:
    any of them
}