rule TTP_XOR_MULT_DOSStub_0c17 {
  strings:
    $key_0c17 = { 58 7f [2] 2c 67 [2] 6b 65 [2] 2c 74 [2] 62 78 [2] 6e 72 [2] 79 79 [2] 62 37 [2] 5f }

  condition:
    any of them
}