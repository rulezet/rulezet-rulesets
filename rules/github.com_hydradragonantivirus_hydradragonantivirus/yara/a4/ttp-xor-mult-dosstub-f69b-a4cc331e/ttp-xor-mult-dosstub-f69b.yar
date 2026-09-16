rule TTP_XOR_MULT_DOSStub_f69b {
  strings:
    $key_f69b = { a2 f3 [2] d6 eb [2] 91 e9 [2] d6 f8 [2] 98 f4 [2] 94 fe [2] 83 f5 [2] 98 bb [2] a5 }

  condition:
    any of them
}