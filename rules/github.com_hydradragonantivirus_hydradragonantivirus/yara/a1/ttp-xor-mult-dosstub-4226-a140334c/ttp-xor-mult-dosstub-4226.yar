rule TTP_XOR_MULT_DOSStub_4226 {
  strings:
    $key_4226 = { 16 4e [2] 62 56 [2] 25 54 [2] 62 45 [2] 2c 49 [2] 20 43 [2] 37 48 [2] 2c 06 [2] 11 }

  condition:
    any of them
}