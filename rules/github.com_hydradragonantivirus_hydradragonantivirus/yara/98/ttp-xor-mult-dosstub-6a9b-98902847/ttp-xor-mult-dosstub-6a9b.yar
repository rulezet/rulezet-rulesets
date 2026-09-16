rule TTP_XOR_MULT_DOSStub_6a9b {
  strings:
    $key_6a9b = { 3e f3 [2] 4a eb [2] 0d e9 [2] 4a f8 [2] 04 f4 [2] 08 fe [2] 1f f5 [2] 04 bb [2] 39 }

  condition:
    any of them
}