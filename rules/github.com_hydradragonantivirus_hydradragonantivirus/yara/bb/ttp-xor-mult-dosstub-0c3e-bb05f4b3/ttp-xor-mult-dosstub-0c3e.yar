rule TTP_XOR_MULT_DOSStub_0c3e {
  strings:
    $key_0c3e = { 58 56 [2] 2c 4e [2] 6b 4c [2] 2c 5d [2] 62 51 [2] 6e 5b [2] 79 50 [2] 62 1e [2] 5f }

  condition:
    any of them
}