rule TTP_XOR_MULT_DOSStub_6198 {
  strings:
    $key_6198 = { 35 f0 [2] 41 e8 [2] 06 ea [2] 41 fb [2] 0f f7 [2] 03 fd [2] 14 f6 [2] 0f b8 [2] 32 }

  condition:
    any of them
}