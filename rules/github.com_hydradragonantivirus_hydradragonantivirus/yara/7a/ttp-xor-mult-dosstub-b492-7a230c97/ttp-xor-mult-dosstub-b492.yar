rule TTP_XOR_MULT_DOSStub_b492 {
  strings:
    $key_b492 = { e0 fa [2] 94 e2 [2] d3 e0 [2] 94 f1 [2] da fd [2] d6 f7 [2] c1 fc [2] da b2 [2] e7 }

  condition:
    any of them
}