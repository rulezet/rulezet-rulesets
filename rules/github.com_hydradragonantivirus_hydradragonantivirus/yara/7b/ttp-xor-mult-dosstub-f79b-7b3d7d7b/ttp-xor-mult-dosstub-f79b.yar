rule TTP_XOR_MULT_DOSStub_f79b {
  strings:
    $key_f79b = { a3 f3 [2] d7 eb [2] 90 e9 [2] d7 f8 [2] 99 f4 [2] 95 fe [2] 82 f5 [2] 99 bb [2] a4 }

  condition:
    any of them
}