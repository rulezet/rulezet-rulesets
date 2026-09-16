rule TTP_XOR_MULT_DOSStub_5992 {
  strings:
    $key_5992 = { 0d fa [2] 79 e2 [2] 3e e0 [2] 79 f1 [2] 37 fd [2] 3b f7 [2] 2c fc [2] 37 b2 [2] 0a }

  condition:
    any of them
}