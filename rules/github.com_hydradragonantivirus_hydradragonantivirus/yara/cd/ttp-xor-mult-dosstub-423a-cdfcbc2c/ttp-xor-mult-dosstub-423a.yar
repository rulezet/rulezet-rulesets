rule TTP_XOR_MULT_DOSStub_423a {
  strings:
    $key_423a = { 16 52 [2] 62 4a [2] 25 48 [2] 62 59 [2] 2c 55 [2] 20 5f [2] 37 54 [2] 2c 1a [2] 11 }

  condition:
    any of them
}