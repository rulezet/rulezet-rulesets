rule TTP_XOR_MULT_DOSStub_739b {
  strings:
    $key_739b = { 27 f3 [2] 53 eb [2] 14 e9 [2] 53 f8 [2] 1d f4 [2] 11 fe [2] 06 f5 [2] 1d bb [2] 20 }

  condition:
    any of them
}