rule TTP_XOR_MULT_DOSStub_0c41 {
  strings:
    $key_0c41 = { 58 29 [2] 2c 31 [2] 6b 33 [2] 2c 22 [2] 62 2e [2] 6e 24 [2] 79 2f [2] 62 61 [2] 5f }

  condition:
    any of them
}