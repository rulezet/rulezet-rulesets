rule TTP_XOR_MULT_DOSStub_4d8b {
  strings:
    $key_4d8b = { 19 e3 [2] 6d fb [2] 2a f9 [2] 6d e8 [2] 23 e4 [2] 2f ee [2] 38 e5 [2] 23 ab [2] 1e }

  condition:
    any of them
}