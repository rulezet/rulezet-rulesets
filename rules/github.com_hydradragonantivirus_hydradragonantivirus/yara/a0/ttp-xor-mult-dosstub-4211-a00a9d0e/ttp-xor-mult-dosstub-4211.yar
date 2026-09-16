rule TTP_XOR_MULT_DOSStub_4211 {
  strings:
    $key_4211 = { 16 79 [2] 62 61 [2] 25 63 [2] 62 72 [2] 2c 7e [2] 20 74 [2] 37 7f [2] 2c 31 [2] 11 }

  condition:
    any of them
}