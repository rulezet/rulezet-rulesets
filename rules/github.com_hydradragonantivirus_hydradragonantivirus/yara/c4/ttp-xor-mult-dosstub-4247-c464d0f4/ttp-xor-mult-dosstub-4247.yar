rule TTP_XOR_MULT_DOSStub_4247 {
  strings:
    $key_4247 = { 16 2f [2] 62 37 [2] 25 35 [2] 62 24 [2] 2c 28 [2] 20 22 [2] 37 29 [2] 2c 67 [2] 11 }

  condition:
    any of them
}