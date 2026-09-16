rule TTP_XOR_MULT_DOSStub_42f6 {
  strings:
    $key_42f6 = { 16 9e [2] 62 86 [2] 25 84 [2] 62 95 [2] 2c 99 [2] 20 93 [2] 37 98 [2] 2c d6 [2] 11 }

  condition:
    any of them
}