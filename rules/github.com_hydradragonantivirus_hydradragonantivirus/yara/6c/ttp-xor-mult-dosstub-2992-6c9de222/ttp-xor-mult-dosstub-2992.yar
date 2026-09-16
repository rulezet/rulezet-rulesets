rule TTP_XOR_MULT_DOSStub_2992 {
  strings:
    $key_2992 = { 7d fa [2] 09 e2 [2] 4e e0 [2] 09 f1 [2] 47 fd [2] 4b f7 [2] 5c fc [2] 47 b2 [2] 7a }

  condition:
    any of them
}