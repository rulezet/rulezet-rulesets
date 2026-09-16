rule TTP_XOR_MULT_DOSStub_ef92 {
  strings:
    $key_ef92 = { bb fa [2] cf e2 [2] 88 e0 [2] cf f1 [2] 81 fd [2] 8d f7 [2] 9a fc [2] 81 b2 [2] bc }

  condition:
    any of them
}