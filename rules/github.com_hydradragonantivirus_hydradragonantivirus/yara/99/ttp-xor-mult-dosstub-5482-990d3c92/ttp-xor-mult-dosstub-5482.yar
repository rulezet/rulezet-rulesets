rule TTP_XOR_MULT_DOSStub_5482 {
  strings:
    $key_5482 = { 00 ea [2] 74 f2 [2] 33 f0 [2] 74 e1 [2] 3a ed [2] 36 e7 [2] 21 ec [2] 3a a2 [2] 07 }

  condition:
    any of them
}