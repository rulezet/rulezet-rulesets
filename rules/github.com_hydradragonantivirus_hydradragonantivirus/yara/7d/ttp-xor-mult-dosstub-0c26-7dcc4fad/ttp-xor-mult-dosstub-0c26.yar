rule TTP_XOR_MULT_DOSStub_0c26 {
  strings:
    $key_0c26 = { 58 4e [2] 2c 56 [2] 6b 54 [2] 2c 45 [2] 62 49 [2] 6e 43 [2] 79 48 [2] 62 06 [2] 5f }

  condition:
    any of them
}