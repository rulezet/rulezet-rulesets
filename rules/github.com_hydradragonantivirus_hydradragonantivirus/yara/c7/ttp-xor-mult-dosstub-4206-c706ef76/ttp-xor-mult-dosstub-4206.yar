rule TTP_XOR_MULT_DOSStub_4206 {
  strings:
    $key_4206 = { 16 6e [2] 62 76 [2] 25 74 [2] 62 65 [2] 2c 69 [2] 20 63 [2] 37 68 [2] 2c 26 [2] 11 }

  condition:
    any of them
}