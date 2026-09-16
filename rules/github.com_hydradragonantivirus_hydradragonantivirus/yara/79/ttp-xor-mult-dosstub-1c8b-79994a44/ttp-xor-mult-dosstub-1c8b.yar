rule TTP_XOR_MULT_DOSStub_1c8b {
  strings:
    $key_1c8b = { 48 e3 [2] 3c fb [2] 7b f9 [2] 3c e8 [2] 72 e4 [2] 7e ee [2] 69 e5 [2] 72 ab [2] 4f }

  condition:
    any of them
}