rule TTP_XOR_MULT_DOSStub_5098 {
  strings:
    $key_5098 = { 04 f0 [2] 70 e8 [2] 37 ea [2] 70 fb [2] 3e f7 [2] 32 fd [2] 25 f6 [2] 3e b8 [2] 03 }

  condition:
    any of them
}