rule TTP_XOR_MULT_DOSStub_0c71 {
  strings:
    $key_0c71 = { 58 19 [2] 2c 01 [2] 6b 03 [2] 2c 12 [2] 62 1e [2] 6e 14 [2] 79 1f [2] 62 51 [2] 5f }

  condition:
    any of them
}