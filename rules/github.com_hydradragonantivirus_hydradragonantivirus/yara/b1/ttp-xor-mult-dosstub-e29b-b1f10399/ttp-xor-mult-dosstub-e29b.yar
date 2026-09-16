rule TTP_XOR_MULT_DOSStub_e29b {
  strings:
    $key_e29b = { b6 f3 [2] c2 eb [2] 85 e9 [2] c2 f8 [2] 8c f4 [2] 80 fe [2] 97 f5 [2] 8c bb [2] b1 }

  condition:
    any of them
}