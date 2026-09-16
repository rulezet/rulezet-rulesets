rule TTP_XOR_MULT_DOSStub_4263 {
  strings:
    $key_4263 = { 16 0b [2] 62 13 [2] 25 11 [2] 62 00 [2] 2c 0c [2] 20 06 [2] 37 0d [2] 2c 43 [2] 11 }

  condition:
    any of them
}