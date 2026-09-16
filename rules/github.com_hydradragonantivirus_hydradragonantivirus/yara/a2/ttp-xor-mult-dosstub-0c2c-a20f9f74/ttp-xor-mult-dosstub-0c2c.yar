rule TTP_XOR_MULT_DOSStub_0c2c {
  strings:
    $key_0c2c = { 58 44 [2] 2c 5c [2] 6b 5e [2] 2c 4f [2] 62 43 [2] 6e 49 [2] 79 42 [2] 62 0c [2] 5f }

  condition:
    any of them
}