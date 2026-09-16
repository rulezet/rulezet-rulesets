rule TTP_XOR_MULT_DOSStub_4e8b {
  strings:
    $key_4e8b = { 1a e3 [2] 6e fb [2] 29 f9 [2] 6e e8 [2] 20 e4 [2] 2c ee [2] 3b e5 [2] 20 ab [2] 1d }

  condition:
    any of them
}