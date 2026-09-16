rule TTP_XOR_MULT_DOSStub_4246 {
  strings:
    $key_4246 = { 16 2e [2] 62 36 [2] 25 34 [2] 62 25 [2] 2c 29 [2] 20 23 [2] 37 28 [2] 2c 66 [2] 11 }

  condition:
    any of them
}