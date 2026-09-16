rule TTP_XOR_MULT_DOSStub_f598 {
  strings:
    $key_f598 = { a1 f0 [2] d5 e8 [2] 92 ea [2] d5 fb [2] 9b f7 [2] 97 fd [2] 80 f6 [2] 9b b8 [2] a6 }

  condition:
    any of them
}