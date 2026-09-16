rule TTP_XOR_MULT_DOSStub_2c1a {
  strings:
    $key_2c1a = { 78 72 [2] 0c 6a [2] 4b 68 [2] 0c 79 [2] 42 75 [2] 4e 7f [2] 59 74 [2] 42 3a [2] 7f }

  condition:
    any of them
}