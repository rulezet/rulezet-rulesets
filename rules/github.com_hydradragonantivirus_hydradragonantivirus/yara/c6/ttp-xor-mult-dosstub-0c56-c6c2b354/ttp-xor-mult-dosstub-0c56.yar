rule TTP_XOR_MULT_DOSStub_0c56 {
  strings:
    $key_0c56 = { 58 3e [2] 2c 26 [2] 6b 24 [2] 2c 35 [2] 62 39 [2] 6e 33 [2] 79 38 [2] 62 76 [2] 5f }

  condition:
    any of them
}