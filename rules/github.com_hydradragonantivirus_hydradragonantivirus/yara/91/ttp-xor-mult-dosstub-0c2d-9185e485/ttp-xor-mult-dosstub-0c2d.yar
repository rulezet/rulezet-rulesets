rule TTP_XOR_MULT_DOSStub_0c2d {
  strings:
    $key_0c2d = { 58 45 [2] 2c 5d [2] 6b 5f [2] 2c 4e [2] 62 42 [2] 6e 48 [2] 79 43 [2] 62 0d [2] 5f }

  condition:
    any of them
}