rule TTP_XOR_MULT_DOSStub_f39b {
  strings:
    $key_f39b = { a7 f3 [2] d3 eb [2] 94 e9 [2] d3 f8 [2] 9d f4 [2] 91 fe [2] 86 f5 [2] 9d bb [2] a0 }

  condition:
    any of them
}