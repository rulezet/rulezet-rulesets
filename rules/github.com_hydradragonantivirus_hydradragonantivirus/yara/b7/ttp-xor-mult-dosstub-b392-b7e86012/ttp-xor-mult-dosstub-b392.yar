rule TTP_XOR_MULT_DOSStub_b392 {
  strings:
    $key_b392 = { e7 fa [2] 93 e2 [2] d4 e0 [2] 93 f1 [2] dd fd [2] d1 f7 [2] c6 fc [2] dd b2 [2] e0 }

  condition:
    any of them
}