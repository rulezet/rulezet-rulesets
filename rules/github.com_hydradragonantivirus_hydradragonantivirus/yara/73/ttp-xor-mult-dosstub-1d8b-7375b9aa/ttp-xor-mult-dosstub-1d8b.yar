rule TTP_XOR_MULT_DOSStub_1d8b {
  strings:
    $key_1d8b = { 49 e3 [2] 3d fb [2] 7a f9 [2] 3d e8 [2] 73 e4 [2] 7f ee [2] 68 e5 [2] 73 ab [2] 4e }

  condition:
    any of them
}