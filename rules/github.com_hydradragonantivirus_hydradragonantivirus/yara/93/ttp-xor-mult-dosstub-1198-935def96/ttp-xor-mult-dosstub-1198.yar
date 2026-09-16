rule TTP_XOR_MULT_DOSStub_1198 {
  strings:
    $key_1198 = { 45 f0 [2] 31 e8 [2] 76 ea [2] 31 fb [2] 7f f7 [2] 73 fd [2] 64 f6 [2] 7f b8 [2] 42 }

  condition:
    any of them
}