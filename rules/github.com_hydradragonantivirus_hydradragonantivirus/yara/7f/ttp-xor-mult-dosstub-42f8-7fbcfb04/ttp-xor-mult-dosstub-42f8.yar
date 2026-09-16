rule TTP_XOR_MULT_DOSStub_42f8 {
  strings:
    $key_42f8 = { 16 90 [2] 62 88 [2] 25 8a [2] 62 9b [2] 2c 97 [2] 20 9d [2] 37 96 [2] 2c d8 [2] 11 }

  condition:
    any of them
}