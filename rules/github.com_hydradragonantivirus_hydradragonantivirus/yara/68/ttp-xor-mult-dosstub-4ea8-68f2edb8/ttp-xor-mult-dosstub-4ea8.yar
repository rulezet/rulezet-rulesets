rule TTP_XOR_MULT_DOSStub_4ea8 {
  strings:
    $key_4ea8 = { 1a c0 [2] 6e d8 [2] 29 da [2] 6e cb [2] 20 c7 [2] 2c cd [2] 3b c6 [2] 20 88 [2] 1d }

  condition:
    any of them
}