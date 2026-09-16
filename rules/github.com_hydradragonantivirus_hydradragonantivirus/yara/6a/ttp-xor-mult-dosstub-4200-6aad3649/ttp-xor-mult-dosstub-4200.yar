rule TTP_XOR_MULT_DOSStub_4200 {
  strings:
    $key_4200 = { 16 68 [2] 62 70 [2] 25 72 [2] 62 63 [2] 2c 6f [2] 20 65 [2] 37 6e [2] 2c 20 [2] 11 }

  condition:
    any of them
}