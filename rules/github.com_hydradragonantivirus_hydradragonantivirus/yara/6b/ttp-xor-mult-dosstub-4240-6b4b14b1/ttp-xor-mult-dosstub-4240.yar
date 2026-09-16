rule TTP_XOR_MULT_DOSStub_4240 {
  strings:
    $key_4240 = { 16 28 [2] 62 30 [2] 25 32 [2] 62 23 [2] 2c 2f [2] 20 25 [2] 37 2e [2] 2c 60 [2] 11 }

  condition:
    any of them
}