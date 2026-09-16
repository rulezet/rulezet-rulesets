rule TTP_XOR_MULT_DOSStub_4198 {
  strings:
    $key_4198 = { 15 f0 [2] 61 e8 [2] 26 ea [2] 61 fb [2] 2f f7 [2] 23 fd [2] 34 f6 [2] 2f b8 [2] 12 }

  condition:
    any of them
}