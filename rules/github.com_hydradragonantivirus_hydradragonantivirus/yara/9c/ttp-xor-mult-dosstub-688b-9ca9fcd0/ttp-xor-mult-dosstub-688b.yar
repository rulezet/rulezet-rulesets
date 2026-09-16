rule TTP_XOR_MULT_DOSStub_688b {
  strings:
    $key_688b = { 3c e3 [2] 48 fb [2] 0f f9 [2] 48 e8 [2] 06 e4 [2] 0a ee [2] 1d e5 [2] 06 ab [2] 3b }

  condition:
    any of them
}