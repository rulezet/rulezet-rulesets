rule TTP_XOR_MULT_DOSStub_fb9b {
  strings:
    $key_fb9b = { af f3 [2] db eb [2] 9c e9 [2] db f8 [2] 95 f4 [2] 99 fe [2] 8e f5 [2] 95 bb [2] a8 }

  condition:
    any of them
}