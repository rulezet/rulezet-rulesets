rule TTP_XOR_MULT_DOSStub_3282 {
  strings:
    $key_3282 = { 66 ea [2] 12 f2 [2] 55 f0 [2] 12 e1 [2] 5c ed [2] 50 e7 [2] 47 ec [2] 5c a2 [2] 61 }

  condition:
    any of them
}