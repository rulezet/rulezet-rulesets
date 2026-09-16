rule TTP_XOR_MULT_DOSStub_5d8b {
  strings:
    $key_5d8b = { 09 e3 [2] 7d fb [2] 3a f9 [2] 7d e8 [2] 33 e4 [2] 3f ee [2] 28 e5 [2] 33 ab [2] 0e }

  condition:
    any of them
}