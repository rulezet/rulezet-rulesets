rule TTP_XOR_MULT_DOSStub_0b9b {
  strings:
    $key_0b9b = { 5f f3 [2] 2b eb [2] 6c e9 [2] 2b f8 [2] 65 f4 [2] 69 fe [2] 7e f5 [2] 65 bb [2] 58 }

  condition:
    any of them
}