rule TTP_XOR_MULT_DOSStub_ef9b {
  strings:
    $key_ef9b = { bb f3 [2] cf eb [2] 88 e9 [2] cf f8 [2] 81 f4 [2] 8d fe [2] 9a f5 [2] 81 bb [2] bc }

  condition:
    any of them
}