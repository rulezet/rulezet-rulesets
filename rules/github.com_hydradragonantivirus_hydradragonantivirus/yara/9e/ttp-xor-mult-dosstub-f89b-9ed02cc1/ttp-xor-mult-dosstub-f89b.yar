rule TTP_XOR_MULT_DOSStub_f89b {
  strings:
    $key_f89b = { ac f3 [2] d8 eb [2] 9f e9 [2] d8 f8 [2] 96 f4 [2] 9a fe [2] 8d f5 [2] 96 bb [2] ab }

  condition:
    any of them
}