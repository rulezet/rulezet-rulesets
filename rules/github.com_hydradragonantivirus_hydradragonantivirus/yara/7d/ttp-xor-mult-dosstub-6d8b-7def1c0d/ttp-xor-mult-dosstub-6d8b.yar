rule TTP_XOR_MULT_DOSStub_6d8b {
  strings:
    $key_6d8b = { 39 e3 [2] 4d fb [2] 0a f9 [2] 4d e8 [2] 03 e4 [2] 0f ee [2] 18 e5 [2] 03 ab [2] 3e }

  condition:
    any of them
}