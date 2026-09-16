rule TTP_XOR_MULT_DOSStub_1a9b {
  strings:
    $key_1a9b = { 4e f3 [2] 3a eb [2] 7d e9 [2] 3a f8 [2] 74 f4 [2] 78 fe [2] 6f f5 [2] 74 bb [2] 49 }

  condition:
    any of them
}