rule TTP_XOR_MULT_DOSStub_2e9a {
  strings:
    $key_2e9a = { 7a f2 [2] 0e ea [2] 49 e8 [2] 0e f9 [2] 40 f5 [2] 4c ff [2] 5b f4 [2] 40 ba [2] 7d }

  condition:
    any of them
}