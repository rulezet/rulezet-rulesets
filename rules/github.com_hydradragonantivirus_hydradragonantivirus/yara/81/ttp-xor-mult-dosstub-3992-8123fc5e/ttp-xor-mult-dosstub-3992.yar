rule TTP_XOR_MULT_DOSStub_3992 {
  strings:
    $key_3992 = { 6d fa [2] 19 e2 [2] 5e e0 [2] 19 f1 [2] 57 fd [2] 5b f7 [2] 4c fc [2] 57 b2 [2] 6a }

  condition:
    any of them
}