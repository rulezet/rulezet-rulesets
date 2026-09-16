rule TTP_XOR_MULT_DOSStub_3b9b {
  strings:
    $key_3b9b = { 6f f3 [2] 1b eb [2] 5c e9 [2] 1b f8 [2] 55 f4 [2] 59 fe [2] 4e f5 [2] 55 bb [2] 68 }

  condition:
    any of them
}