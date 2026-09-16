rule TTP_XOR_MULT_DOSStub_b69b {
  strings:
    $key_b69b = { e2 f3 [2] 96 eb [2] d1 e9 [2] 96 f8 [2] d8 f4 [2] d4 fe [2] c3 f5 [2] d8 bb [2] e5 }

  condition:
    any of them
}