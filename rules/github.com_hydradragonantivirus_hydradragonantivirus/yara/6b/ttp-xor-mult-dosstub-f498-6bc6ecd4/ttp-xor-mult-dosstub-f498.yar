rule TTP_XOR_MULT_DOSStub_f498 {
  strings:
    $key_f498 = { a0 f0 [2] d4 e8 [2] 93 ea [2] d4 fb [2] 9a f7 [2] 96 fd [2] 81 f6 [2] 9a b8 [2] a7 }

  condition:
    any of them
}