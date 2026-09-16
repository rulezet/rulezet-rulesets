rule TTP_XOR_MULT_DOSStub_6b8b {
  strings:
    $key_6b8b = { 3f e3 [2] 4b fb [2] 0c f9 [2] 4b e8 [2] 05 e4 [2] 09 ee [2] 1e e5 [2] 05 ab [2] 38 }

  condition:
    any of them
}