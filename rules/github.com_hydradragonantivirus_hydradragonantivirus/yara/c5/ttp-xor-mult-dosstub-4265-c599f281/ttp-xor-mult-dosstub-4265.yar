rule TTP_XOR_MULT_DOSStub_4265 {
  strings:
    $key_4265 = { 16 0d [2] 62 15 [2] 25 17 [2] 62 06 [2] 2c 0a [2] 20 00 [2] 37 0b [2] 2c 45 [2] 11 }

  condition:
    any of them
}