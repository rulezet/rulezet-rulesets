rule TTP_XOR_MULT_DOSStub_b796 {
  strings:
    $key_b796 = { e3 fe [2] 97 e6 [2] d0 e4 [2] 97 f5 [2] d9 f9 [2] d5 f3 [2] c2 f8 [2] d9 b6 [2] e4 }

  condition:
    any of them
}