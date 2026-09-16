rule TTP_XOR_MULT_DOSStub_f489 {
  strings:
    $key_f489 = { a0 e1 [2] d4 f9 [2] 93 fb [2] d4 ea [2] 9a e6 [2] 96 ec [2] 81 e7 [2] 9a a9 [2] a7 }

  condition:
    any of them
}