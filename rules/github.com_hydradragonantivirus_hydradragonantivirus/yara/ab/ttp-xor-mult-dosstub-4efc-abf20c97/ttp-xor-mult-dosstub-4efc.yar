rule TTP_XOR_MULT_DOSStub_4efc {
  strings:
    $key_4efc = { 1a 94 [2] 6e 8c [2] 29 8e [2] 6e 9f [2] 20 93 [2] 2c 99 [2] 3b 92 [2] 20 dc [2] 1d }

  condition:
    any of them
}