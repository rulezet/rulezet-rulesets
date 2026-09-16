rule TTP_XOR_MULT_DOSStub_f298 {
  strings:
    $key_f298 = { a6 f0 [2] d2 e8 [2] 95 ea [2] d2 fb [2] 9c f7 [2] 90 fd [2] 87 f6 [2] 9c b8 [2] a1 }

  condition:
    any of them
}