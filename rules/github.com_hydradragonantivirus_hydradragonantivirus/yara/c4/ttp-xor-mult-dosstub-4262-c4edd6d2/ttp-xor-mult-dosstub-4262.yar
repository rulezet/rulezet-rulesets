rule TTP_XOR_MULT_DOSStub_4262 {
  strings:
    $key_4262 = { 16 0a [2] 62 12 [2] 25 10 [2] 62 01 [2] 2c 0d [2] 20 07 [2] 37 0c [2] 2c 42 [2] 11 }

  condition:
    any of them
}