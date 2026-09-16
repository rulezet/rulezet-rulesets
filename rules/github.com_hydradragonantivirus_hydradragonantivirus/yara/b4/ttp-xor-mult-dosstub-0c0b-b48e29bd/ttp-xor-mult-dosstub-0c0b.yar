rule TTP_XOR_MULT_DOSStub_0c0b {
  strings:
    $key_0c0b = { 58 63 [2] 2c 7b [2] 6b 79 [2] 2c 68 [2] 62 64 [2] 6e 6e [2] 79 65 [2] 62 2b [2] 5f }

  condition:
    any of them
}