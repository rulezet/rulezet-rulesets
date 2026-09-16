rule TTP_XOR_MULT_DOSStub_7a8b {
  strings:
    $key_7a8b = { 2e e3 [2] 5a fb [2] 1d f9 [2] 5a e8 [2] 14 e4 [2] 18 ee [2] 0f e5 [2] 14 ab [2] 29 }

  condition:
    any of them
}