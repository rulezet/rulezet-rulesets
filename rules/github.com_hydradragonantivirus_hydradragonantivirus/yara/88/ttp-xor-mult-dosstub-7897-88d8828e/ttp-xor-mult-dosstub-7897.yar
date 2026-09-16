rule TTP_XOR_MULT_DOSStub_7897 {
  strings:
    $key_7897 = { 2c ff [2] 58 e7 [2] 1f e5 [2] 58 f4 [2] 16 f8 [2] 1a f2 [2] 0d f9 [2] 16 b7 [2] 2b }

  condition:
    any of them
}