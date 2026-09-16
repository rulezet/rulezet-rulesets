rule TTP_XOR_MULT_DOSStub_5198 {
  strings:
    $key_5198 = { 05 f0 [2] 71 e8 [2] 36 ea [2] 71 fb [2] 3f f7 [2] 33 fd [2] 24 f6 [2] 3f b8 [2] 02 }

  condition:
    any of them
}