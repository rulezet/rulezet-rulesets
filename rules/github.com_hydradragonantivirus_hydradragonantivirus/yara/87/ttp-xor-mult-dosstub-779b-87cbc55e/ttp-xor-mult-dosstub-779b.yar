rule TTP_XOR_MULT_DOSStub_779b {
  strings:
    $key_779b = { 23 f3 [2] 57 eb [2] 10 e9 [2] 57 f8 [2] 19 f4 [2] 15 fe [2] 02 f5 [2] 19 bb [2] 24 }

  condition:
    any of them
}