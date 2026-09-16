rule TTP_XOR_MULT_DOSStub_2a8b {
  strings:
    $key_2a8b = { 7e e3 [2] 0a fb [2] 4d f9 [2] 0a e8 [2] 44 e4 [2] 48 ee [2] 5f e5 [2] 44 ab [2] 79 }

  condition:
    any of them
}