rule TTP_XOR_MULT_DOSStub_4e9a {
  strings:
    $key_4e9a = { 1a f2 [2] 6e ea [2] 29 e8 [2] 6e f9 [2] 20 f5 [2] 2c ff [2] 3b f4 [2] 20 ba [2] 1d }

  condition:
    any of them
}