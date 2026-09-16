rule TTP_XOR_MULT_DOSStub_4269 {
  strings:
    $key_4269 = { 16 01 [2] 62 19 [2] 25 1b [2] 62 0a [2] 2c 06 [2] 20 0c [2] 37 07 [2] 2c 49 [2] 11 }

  condition:
    any of them
}