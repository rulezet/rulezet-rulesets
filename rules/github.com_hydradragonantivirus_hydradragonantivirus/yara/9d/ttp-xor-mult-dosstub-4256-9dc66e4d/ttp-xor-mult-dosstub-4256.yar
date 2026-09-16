rule TTP_XOR_MULT_DOSStub_4256 {
  strings:
    $key_4256 = { 16 3e [2] 62 26 [2] 25 24 [2] 62 35 [2] 2c 39 [2] 20 33 [2] 37 38 [2] 2c 76 [2] 11 }

  condition:
    any of them
}