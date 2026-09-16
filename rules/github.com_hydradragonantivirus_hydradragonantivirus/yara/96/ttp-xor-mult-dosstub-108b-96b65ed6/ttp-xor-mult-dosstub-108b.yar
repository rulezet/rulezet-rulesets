rule TTP_XOR_MULT_DOSStub_108b {
  strings:
    $key_108b = { 44 e3 [2] 30 fb [2] 77 f9 [2] 30 e8 [2] 7e e4 [2] 72 ee [2] 65 e5 [2] 7e ab [2] 43 }

  condition:
    any of them
}