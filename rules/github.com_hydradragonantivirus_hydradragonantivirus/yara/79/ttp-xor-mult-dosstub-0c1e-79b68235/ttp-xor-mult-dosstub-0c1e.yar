rule TTP_XOR_MULT_DOSStub_0c1e {
  strings:
    $key_0c1e = { 58 76 [2] 2c 6e [2] 6b 6c [2] 2c 7d [2] 62 71 [2] 6e 7b [2] 79 70 [2] 62 3e [2] 5f }

  condition:
    any of them
}