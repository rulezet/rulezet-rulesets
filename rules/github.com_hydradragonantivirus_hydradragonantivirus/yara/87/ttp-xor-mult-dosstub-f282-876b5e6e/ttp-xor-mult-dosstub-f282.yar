rule TTP_XOR_MULT_DOSStub_f282 {
  strings:
    $key_f282 = { a6 ea [2] d2 f2 [2] 95 f0 [2] d2 e1 [2] 9c ed [2] 90 e7 [2] 87 ec [2] 9c a2 [2] a1 }

  condition:
    any of them
}