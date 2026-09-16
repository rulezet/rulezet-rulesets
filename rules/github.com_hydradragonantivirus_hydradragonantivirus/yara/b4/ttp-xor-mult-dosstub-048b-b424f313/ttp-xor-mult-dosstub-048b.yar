rule TTP_XOR_MULT_DOSStub_048b {
  strings:
    $key_048b = { 50 e3 [2] 24 fb [2] 63 f9 [2] 24 e8 [2] 6a e4 [2] 66 ee [2] 71 e5 [2] 6a ab [2] 57 }

  condition:
    any of them
}