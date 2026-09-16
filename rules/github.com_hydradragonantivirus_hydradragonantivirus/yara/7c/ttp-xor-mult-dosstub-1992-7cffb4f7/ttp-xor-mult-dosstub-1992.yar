rule TTP_XOR_MULT_DOSStub_1992 {
  strings:
    $key_1992 = { 4d fa [2] 39 e2 [2] 7e e0 [2] 39 f1 [2] 77 fd [2] 7b f7 [2] 6c fc [2] 77 b2 [2] 4a }

  condition:
    any of them
}