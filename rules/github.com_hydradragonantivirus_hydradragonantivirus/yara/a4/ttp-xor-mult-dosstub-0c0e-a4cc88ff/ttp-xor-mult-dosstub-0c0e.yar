rule TTP_XOR_MULT_DOSStub_0c0e {
  strings:
    $key_0c0e = { 58 66 [2] 2c 7e [2] 6b 7c [2] 2c 6d [2] 62 61 [2] 6e 6b [2] 79 60 [2] 62 2e [2] 5f }

  condition:
    any of them
}