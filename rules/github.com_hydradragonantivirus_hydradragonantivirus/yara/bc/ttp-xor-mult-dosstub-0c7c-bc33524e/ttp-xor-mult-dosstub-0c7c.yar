rule TTP_XOR_MULT_DOSStub_0c7c {
  strings:
    $key_0c7c = { 58 14 [2] 2c 0c [2] 6b 0e [2] 2c 1f [2] 62 13 [2] 6e 19 [2] 79 12 [2] 62 5c [2] 5f }

  condition:
    any of them
}