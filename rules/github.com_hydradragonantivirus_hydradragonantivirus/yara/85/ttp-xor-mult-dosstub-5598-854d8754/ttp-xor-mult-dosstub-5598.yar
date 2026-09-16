rule TTP_XOR_MULT_DOSStub_5598 {
  strings:
    $key_5598 = { 01 f0 [2] 75 e8 [2] 32 ea [2] 75 fb [2] 3b f7 [2] 37 fd [2] 20 f6 [2] 3b b8 [2] 06 }

  condition:
    any of them
}