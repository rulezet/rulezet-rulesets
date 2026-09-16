rule TTP_XOR_MULT_DOSStub_4a9b {
  strings:
    $key_4a9b = { 1e f3 [2] 6a eb [2] 2d e9 [2] 6a f8 [2] 24 f4 [2] 28 fe [2] 3f f5 [2] 24 bb [2] 19 }

  condition:
    any of them
}