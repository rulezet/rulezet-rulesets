rule TTP_XOR_MULT_DOSStub_b684 {
  strings:
    $key_b684 = { e2 ec [2] 96 f4 [2] d1 f6 [2] 96 e7 [2] d8 eb [2] d4 e1 [2] c3 ea [2] d8 a4 [2] e5 }

  condition:
    any of them
}