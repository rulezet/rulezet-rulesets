rule TTP_XOR_MULT_DOSStub_5e9a {
  strings:
    $key_5e9a = { 0a f2 [2] 7e ea [2] 39 e8 [2] 7e f9 [2] 30 f5 [2] 3c ff [2] 2b f4 [2] 30 ba [2] 0d }

  condition:
    any of them
}