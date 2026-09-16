rule TTP_XOR_MULT_DOSStub_469b {
  strings:
    $key_469b = { 12 f3 [2] 66 eb [2] 21 e9 [2] 66 f8 [2] 28 f4 [2] 24 fe [2] 33 f5 [2] 28 bb [2] 15 }

  condition:
    any of them
}