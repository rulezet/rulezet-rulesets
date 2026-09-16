rule TTP_XOR_MULT_DOSStub_ef9a {
  strings:
    $key_ef9a = { bb f2 [2] cf ea [2] 88 e8 [2] cf f9 [2] 81 f5 [2] 8d ff [2] 9a f4 [2] 81 ba [2] bc }

  condition:
    any of them
}