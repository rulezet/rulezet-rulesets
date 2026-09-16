rule TTP_XOR_MULT_DOSStub_0c5e {
  strings:
    $key_0c5e = { 58 36 [2] 2c 2e [2] 6b 2c [2] 2c 3d [2] 62 31 [2] 6e 3b [2] 79 30 [2] 62 7e [2] 5f }

  condition:
    any of them
}