rule TTP_XOR_MULT_DOSStub_0c20 {
  strings:
    $key_0c20 = { 58 48 [2] 2c 50 [2] 6b 52 [2] 2c 43 [2] 62 4f [2] 6e 45 [2] 79 4e [2] 62 00 [2] 5f }

  condition:
    any of them
}