rule TTP_XOR_MULT_DOSStub_e69b {
  strings:
    $key_e69b = { b2 f3 [2] c6 eb [2] 81 e9 [2] c6 f8 [2] 88 f4 [2] 84 fe [2] 93 f5 [2] 88 bb [2] b5 }

  condition:
    any of them
}