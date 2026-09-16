rule TTP_XOR_MULT_DOSStub_508b {
  strings:
    $key_508b = { 04 e3 [2] 70 fb [2] 37 f9 [2] 70 e8 [2] 3e e4 [2] 32 ee [2] 25 e5 [2] 3e ab [2] 03 }

  condition:
    any of them
}