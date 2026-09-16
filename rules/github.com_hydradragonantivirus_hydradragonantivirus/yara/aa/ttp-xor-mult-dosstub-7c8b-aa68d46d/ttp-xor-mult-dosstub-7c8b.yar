rule TTP_XOR_MULT_DOSStub_7c8b {
  strings:
    $key_7c8b = { 28 e3 [2] 5c fb [2] 1b f9 [2] 5c e8 [2] 12 e4 [2] 1e ee [2] 09 e5 [2] 12 ab [2] 2f }

  condition:
    any of them
}