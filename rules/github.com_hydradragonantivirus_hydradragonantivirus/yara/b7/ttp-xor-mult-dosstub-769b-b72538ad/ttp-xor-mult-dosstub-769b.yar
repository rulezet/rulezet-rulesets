rule TTP_XOR_MULT_DOSStub_769b {
  strings:
    $key_769b = { 22 f3 [2] 56 eb [2] 11 e9 [2] 56 f8 [2] 18 f4 [2] 14 fe [2] 03 f5 [2] 18 bb [2] 25 }

  condition:
    any of them
}