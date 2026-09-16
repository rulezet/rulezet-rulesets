rule TTP_XOR_MULT_DOSStub_6498 {
  strings:
    $key_6498 = { 30 f0 [2] 44 e8 [2] 03 ea [2] 44 fb [2] 0a f7 [2] 06 fd [2] 11 f6 [2] 0a b8 [2] 37 }

  condition:
    any of them
}