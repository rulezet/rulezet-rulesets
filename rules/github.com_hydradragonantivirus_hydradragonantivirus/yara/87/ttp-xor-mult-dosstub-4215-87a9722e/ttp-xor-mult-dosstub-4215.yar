rule TTP_XOR_MULT_DOSStub_4215 {
  strings:
    $key_4215 = { 16 7d [2] 62 65 [2] 25 67 [2] 62 76 [2] 2c 7a [2] 20 70 [2] 37 7b [2] 2c 35 [2] 11 }

  condition:
    any of them
}