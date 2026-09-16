rule TTP_XOR_MULT_DOSStub_b09b {
  strings:
    $key_b09b = { e4 f3 [2] 90 eb [2] d7 e9 [2] 90 f8 [2] de f4 [2] d2 fe [2] c5 f5 [2] de bb [2] e3 }

  condition:
    any of them
}