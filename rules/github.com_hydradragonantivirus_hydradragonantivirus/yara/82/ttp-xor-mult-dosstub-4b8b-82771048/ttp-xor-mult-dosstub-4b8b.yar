rule TTP_XOR_MULT_DOSStub_4b8b {
  strings:
    $key_4b8b = { 1f e3 [2] 6b fb [2] 2c f9 [2] 6b e8 [2] 25 e4 [2] 29 ee [2] 3e e5 [2] 25 ab [2] 18 }

  condition:
    any of them
}