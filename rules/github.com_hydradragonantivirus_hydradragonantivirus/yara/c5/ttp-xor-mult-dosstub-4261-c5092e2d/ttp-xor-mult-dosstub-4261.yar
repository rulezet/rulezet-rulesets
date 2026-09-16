rule TTP_XOR_MULT_DOSStub_4261 {
  strings:
    $key_4261 = { 16 09 [2] 62 11 [2] 25 13 [2] 62 02 [2] 2c 0e [2] 20 04 [2] 37 0f [2] 2c 41 [2] 11 }

  condition:
    any of them
}