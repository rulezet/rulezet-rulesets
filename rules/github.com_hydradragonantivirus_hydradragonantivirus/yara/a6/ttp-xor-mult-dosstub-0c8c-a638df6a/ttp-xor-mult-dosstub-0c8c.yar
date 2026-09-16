rule TTP_XOR_MULT_DOSStub_0c8c {
  strings:
    $key_0c8c = { 58 e4 [2] 2c fc [2] 6b fe [2] 2c ef [2] 62 e3 [2] 6e e9 [2] 79 e2 [2] 62 ac [2] 5f }

  condition:
    any of them
}