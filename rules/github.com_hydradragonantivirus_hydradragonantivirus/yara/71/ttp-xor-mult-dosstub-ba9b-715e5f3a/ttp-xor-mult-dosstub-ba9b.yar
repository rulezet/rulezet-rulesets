rule TTP_XOR_MULT_DOSStub_ba9b {
  strings:
    $key_ba9b = { ee f3 [2] 9a eb [2] dd e9 [2] 9a f8 [2] d4 f4 [2] d8 fe [2] cf f5 [2] d4 bb [2] e9 }

  condition:
    any of them
}