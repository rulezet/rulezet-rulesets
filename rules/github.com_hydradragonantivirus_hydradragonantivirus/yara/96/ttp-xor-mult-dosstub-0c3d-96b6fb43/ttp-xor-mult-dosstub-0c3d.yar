rule TTP_XOR_MULT_DOSStub_0c3d {
  strings:
    $key_0c3d = { 58 55 [2] 2c 4d [2] 6b 4f [2] 2c 5e [2] 62 52 [2] 6e 58 [2] 79 53 [2] 62 1d [2] 5f }

  condition:
    any of them
}