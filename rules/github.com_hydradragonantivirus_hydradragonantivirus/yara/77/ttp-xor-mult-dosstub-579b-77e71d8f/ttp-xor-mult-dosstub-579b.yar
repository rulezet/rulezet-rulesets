rule TTP_XOR_MULT_DOSStub_579b {
  strings:
    $key_579b = { 03 f3 [2] 77 eb [2] 30 e9 [2] 77 f8 [2] 39 f4 [2] 35 fe [2] 22 f5 [2] 39 bb [2] 04 }

  condition:
    any of them
}