rule TTP_XOR_MULT_DOSStub_0c0d {
  strings:
    $key_0c0d = { 58 65 [2] 2c 7d [2] 6b 7f [2] 2c 6e [2] 62 62 [2] 6e 68 [2] 79 63 [2] 62 2d [2] 5f }

  condition:
    any of them
}