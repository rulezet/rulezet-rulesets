rule TTP_XOR_MULT_DOSStub_ef90 {
  strings:
    $key_ef90 = { bb f8 [2] cf e0 [2] 88 e2 [2] cf f3 [2] 81 ff [2] 8d f5 [2] 9a fe [2] 81 b0 [2] bc }

  condition:
    any of them
}