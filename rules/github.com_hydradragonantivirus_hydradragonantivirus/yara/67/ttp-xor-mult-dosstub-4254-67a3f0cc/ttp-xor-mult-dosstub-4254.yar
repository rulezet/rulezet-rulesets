rule TTP_XOR_MULT_DOSStub_4254 {
  strings:
    $key_4254 = { 16 3c [2] 62 24 [2] 25 26 [2] 62 37 [2] 2c 3b [2] 20 31 [2] 37 3a [2] 2c 74 [2] 11 }

  condition:
    any of them
}