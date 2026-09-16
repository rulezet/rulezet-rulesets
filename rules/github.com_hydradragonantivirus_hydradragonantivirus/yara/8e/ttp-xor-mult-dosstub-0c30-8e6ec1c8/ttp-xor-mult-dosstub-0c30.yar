rule TTP_XOR_MULT_DOSStub_0c30 {
  strings:
    $key_0c30 = { 58 58 [2] 2c 40 [2] 6b 42 [2] 2c 53 [2] 62 5f [2] 6e 55 [2] 79 5e [2] 62 10 [2] 5f }

  condition:
    any of them
}