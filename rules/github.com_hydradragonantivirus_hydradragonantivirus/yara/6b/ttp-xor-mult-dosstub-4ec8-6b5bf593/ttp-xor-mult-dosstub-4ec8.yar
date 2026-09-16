rule TTP_XOR_MULT_DOSStub_4ec8 {
  strings:
    $key_4ec8 = { 1a a0 [2] 6e b8 [2] 29 ba [2] 6e ab [2] 20 a7 [2] 2c ad [2] 3b a6 [2] 20 e8 [2] 1d }

  condition:
    any of them
}