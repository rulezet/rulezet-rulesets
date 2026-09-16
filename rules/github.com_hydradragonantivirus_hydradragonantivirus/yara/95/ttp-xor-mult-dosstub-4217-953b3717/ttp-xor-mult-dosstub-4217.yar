rule TTP_XOR_MULT_DOSStub_4217 {
  strings:
    $key_4217 = { 16 7f [2] 62 67 [2] 25 65 [2] 62 74 [2] 2c 78 [2] 20 72 [2] 37 79 [2] 2c 37 [2] 11 }

  condition:
    any of them
}