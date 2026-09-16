rule TTP_XOR_MULT_DOSStub_2398 {
  strings:
    $key_2398 = { 77 f0 [2] 03 e8 [2] 44 ea [2] 03 fb [2] 4d f7 [2] 41 fd [2] 56 f6 [2] 4d b8 [2] 70 }

  condition:
    any of them
}