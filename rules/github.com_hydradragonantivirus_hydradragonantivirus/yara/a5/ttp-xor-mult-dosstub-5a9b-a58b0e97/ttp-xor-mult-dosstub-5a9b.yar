rule TTP_XOR_MULT_DOSStub_5a9b {
  strings:
    $key_5a9b = { 0e f3 [2] 7a eb [2] 3d e9 [2] 7a f8 [2] 34 f4 [2] 38 fe [2] 2f f5 [2] 34 bb [2] 09 }

  condition:
    any of them
}