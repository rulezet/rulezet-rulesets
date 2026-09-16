rule TTP_XOR_MULT_DOSStub_479b {
  strings:
    $key_479b = { 13 f3 [2] 67 eb [2] 20 e9 [2] 67 f8 [2] 29 f4 [2] 25 fe [2] 32 f5 [2] 29 bb [2] 14 }

  condition:
    any of them
}