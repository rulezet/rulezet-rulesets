rule TTP_XOR_MULT_DOSStub_3198 {
  strings:
    $key_3198 = { 65 f0 [2] 11 e8 [2] 56 ea [2] 11 fb [2] 5f f7 [2] 53 fd [2] 44 f6 [2] 5f b8 [2] 62 }

  condition:
    any of them
}