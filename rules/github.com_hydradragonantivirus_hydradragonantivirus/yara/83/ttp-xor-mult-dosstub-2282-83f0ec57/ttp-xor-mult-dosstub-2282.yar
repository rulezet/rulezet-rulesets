rule TTP_XOR_MULT_DOSStub_2282 {
  strings:
    $key_2282 = { 76 ea [2] 02 f2 [2] 45 f0 [2] 02 e1 [2] 4c ed [2] 40 e7 [2] 57 ec [2] 4c a2 [2] 71 }

  condition:
    any of them
}