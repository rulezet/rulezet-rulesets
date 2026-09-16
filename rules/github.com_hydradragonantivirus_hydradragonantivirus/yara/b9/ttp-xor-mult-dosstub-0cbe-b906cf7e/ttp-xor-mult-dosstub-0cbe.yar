rule TTP_XOR_MULT_DOSStub_0cbe {
  strings:
    $key_0cbe = { 58 d6 [2] 2c ce [2] 6b cc [2] 2c dd [2] 62 d1 [2] 6e db [2] 79 d0 [2] 62 9e [2] 5f }

  condition:
    any of them
}