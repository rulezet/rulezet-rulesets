rule TTP_XOR_MULT_DOSStub_7198 {
  strings:
    $key_7198 = { 25 f0 [2] 51 e8 [2] 16 ea [2] 51 fb [2] 1f f7 [2] 13 fd [2] 04 f6 [2] 1f b8 [2] 22 }

  condition:
    any of them
}