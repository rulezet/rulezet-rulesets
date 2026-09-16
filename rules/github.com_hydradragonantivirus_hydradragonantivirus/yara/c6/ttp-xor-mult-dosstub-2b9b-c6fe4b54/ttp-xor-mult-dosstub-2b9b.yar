rule TTP_XOR_MULT_DOSStub_2b9b {
  strings:
    $key_2b9b = { 7f f3 [2] 0b eb [2] 4c e9 [2] 0b f8 [2] 45 f4 [2] 49 fe [2] 5e f5 [2] 45 bb [2] 78 }

  condition:
    any of them
}