rule TTP_XOR_MULT_DOSStub_0c11 {
  strings:
    $key_0c11 = { 58 79 [2] 2c 61 [2] 6b 63 [2] 2c 72 [2] 62 7e [2] 6e 74 [2] 79 7f [2] 62 31 [2] 5f }

  condition:
    any of them
}