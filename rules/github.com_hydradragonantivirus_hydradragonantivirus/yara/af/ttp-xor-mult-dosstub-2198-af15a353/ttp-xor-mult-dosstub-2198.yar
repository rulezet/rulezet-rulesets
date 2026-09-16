rule TTP_XOR_MULT_DOSStub_2198 {
  strings:
    $key_2198 = { 75 f0 [2] 01 e8 [2] 46 ea [2] 01 fb [2] 4f f7 [2] 43 fd [2] 54 f6 [2] 4f b8 [2] 72 }

  condition:
    any of them
}