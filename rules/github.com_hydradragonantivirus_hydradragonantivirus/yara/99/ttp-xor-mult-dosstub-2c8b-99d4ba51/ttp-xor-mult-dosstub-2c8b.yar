rule TTP_XOR_MULT_DOSStub_2c8b {
  strings:
    $key_2c8b = { 78 e3 [2] 0c fb [2] 4b f9 [2] 0c e8 [2] 42 e4 [2] 4e ee [2] 59 e5 [2] 42 ab [2] 7f }

  condition:
    any of them
}