rule TTP_XOR_MULT_DOSStub_4220 {
  strings:
    $key_4220 = { 16 48 [2] 62 50 [2] 25 52 [2] 62 43 [2] 2c 4f [2] 20 45 [2] 37 4e [2] 2c 00 [2] 11 }

  condition:
    any of them
}