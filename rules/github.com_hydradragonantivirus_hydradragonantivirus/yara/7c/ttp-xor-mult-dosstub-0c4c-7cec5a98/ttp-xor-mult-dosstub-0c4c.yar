rule TTP_XOR_MULT_DOSStub_0c4c {
  strings:
    $key_0c4c = { 58 24 [2] 2c 3c [2] 6b 3e [2] 2c 2f [2] 62 23 [2] 6e 29 [2] 79 22 [2] 62 6c [2] 5f }

  condition:
    any of them
}