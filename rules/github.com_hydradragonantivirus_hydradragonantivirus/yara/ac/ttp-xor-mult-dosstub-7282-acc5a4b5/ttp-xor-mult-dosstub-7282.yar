rule TTP_XOR_MULT_DOSStub_7282 {
  strings:
    $key_7282 = { 26 ea [2] 52 f2 [2] 15 f0 [2] 52 e1 [2] 1c ed [2] 10 e7 [2] 07 ec [2] 1c a2 [2] 21 }

  condition:
    any of them
}