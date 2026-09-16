rule TTP_XOR_MULT_DOSStub_0598 {
  strings:
    $key_0598 = { 51 f0 [2] 25 e8 [2] 62 ea [2] 25 fb [2] 6b f7 [2] 67 fd [2] 70 f6 [2] 6b b8 [2] 56 }

  condition:
    any of them
}