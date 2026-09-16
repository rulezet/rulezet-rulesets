rule TTP_XOR_MULT_DOSStub_ef89 {
  strings:
    $key_ef89 = { bb e1 [2] cf f9 [2] 88 fb [2] cf ea [2] 81 e6 [2] 8d ec [2] 9a e7 [2] 81 a9 [2] bc }

  condition:
    any of them
}