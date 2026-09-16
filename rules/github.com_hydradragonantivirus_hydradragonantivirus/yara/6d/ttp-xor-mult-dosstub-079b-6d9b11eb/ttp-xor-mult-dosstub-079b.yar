rule TTP_XOR_MULT_DOSStub_079b {
  strings:
    $key_079b = { 53 f3 [2] 27 eb [2] 60 e9 [2] 27 f8 [2] 69 f4 [2] 65 fe [2] 72 f5 [2] 69 bb [2] 54 }

  condition:
    any of them
}