rule TTP_XOR_MULT_DOSStub_e992 {
  strings:
    $key_e992 = { bd fa [2] c9 e2 [2] 8e e0 [2] c9 f1 [2] 87 fd [2] 8b f7 [2] 9c fc [2] 87 b2 [2] ba }

  condition:
    any of them
}