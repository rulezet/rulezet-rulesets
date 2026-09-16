rule TTP_XOR_MULT_DOSStub_279b {
  strings:
    $key_279b = { 73 f3 [2] 07 eb [2] 40 e9 [2] 07 f8 [2] 49 f4 [2] 45 fe [2] 52 f5 [2] 49 bb [2] 74 }

  condition:
    any of them
}