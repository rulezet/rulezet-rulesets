rule TTP_XOR_MULT_DOSStub_7b9b {
  strings:
    $key_7b9b = { 2f f3 [2] 5b eb [2] 1c e9 [2] 5b f8 [2] 15 f4 [2] 19 fe [2] 0e f5 [2] 15 bb [2] 28 }

  condition:
    any of them
}