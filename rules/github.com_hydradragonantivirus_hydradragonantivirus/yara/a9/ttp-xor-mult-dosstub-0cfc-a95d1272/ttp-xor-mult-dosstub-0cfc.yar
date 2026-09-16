rule TTP_XOR_MULT_DOSStub_0cfc {
  strings:
    $key_0cfc = { 58 94 [2] 2c 8c [2] 6b 8e [2] 2c 9f [2] 62 93 [2] 6e 99 [2] 79 92 [2] 62 dc [2] 5f }

  condition:
    any of them
}