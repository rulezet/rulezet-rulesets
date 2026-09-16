rule TTP_XOR_MULT_DOSStub_4582 {
  strings:
    $key_4582 = { 11 ea [2] 65 f2 [2] 22 f0 [2] 65 e1 [2] 2b ed [2] 27 e7 [2] 30 ec [2] 2b a2 [2] 16 }

  condition:
    any of them
}