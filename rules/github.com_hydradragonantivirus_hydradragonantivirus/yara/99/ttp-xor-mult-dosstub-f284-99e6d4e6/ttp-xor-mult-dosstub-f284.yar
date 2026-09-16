rule TTP_XOR_MULT_DOSStub_f284 {
  strings:
    $key_f284 = { a6 ec [2] d2 f4 [2] 95 f6 [2] d2 e7 [2] 9c eb [2] 90 e1 [2] 87 ea [2] 9c a4 [2] a1 }

  condition:
    any of them
}