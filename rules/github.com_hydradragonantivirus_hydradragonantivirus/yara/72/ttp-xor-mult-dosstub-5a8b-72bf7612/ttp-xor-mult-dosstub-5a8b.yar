rule TTP_XOR_MULT_DOSStub_5a8b {
  strings:
    $key_5a8b = { 0e e3 [2] 7a fb [2] 3d f9 [2] 7a e8 [2] 34 e4 [2] 38 ee [2] 2f e5 [2] 34 ab [2] 09 }

  condition:
    any of them
}