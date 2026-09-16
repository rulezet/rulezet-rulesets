rule TTP_XOR_MULT_DOSStub_5b9b {
  strings:
    $key_5b9b = { 0f f3 [2] 7b eb [2] 3c e9 [2] 7b f8 [2] 35 f4 [2] 39 fe [2] 2e f5 [2] 35 bb [2] 08 }

  condition:
    any of them
}