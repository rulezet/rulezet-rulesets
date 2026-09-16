rule TTP_XOR_MULT_DOSStub_0d8b {
  strings:
    $key_0d8b = { 59 e3 [2] 2d fb [2] 6a f9 [2] 2d e8 [2] 63 e4 [2] 6f ee [2] 78 e5 [2] 63 ab [2] 5e }

  condition:
    any of them
}