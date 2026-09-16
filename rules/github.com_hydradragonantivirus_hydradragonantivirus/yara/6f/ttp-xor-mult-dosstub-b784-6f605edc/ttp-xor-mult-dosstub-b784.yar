rule TTP_XOR_MULT_DOSStub_b784 {
  strings:
    $key_b784 = { e3 ec [2] 97 f4 [2] d0 f6 [2] 97 e7 [2] d9 eb [2] d5 e1 [2] c2 ea [2] d9 a4 [2] e4 }

  condition:
    any of them
}