rule TTP_XOR_MULT_DOSStub_2d8b {
  strings:
    $key_2d8b = { 79 e3 [2] 0d fb [2] 4a f9 [2] 0d e8 [2] 43 e4 [2] 4f ee [2] 58 e5 [2] 43 ab [2] 7e }

  condition:
    any of them
}