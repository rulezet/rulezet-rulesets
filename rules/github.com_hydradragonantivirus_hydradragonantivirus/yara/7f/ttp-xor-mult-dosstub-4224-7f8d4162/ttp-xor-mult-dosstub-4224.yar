rule TTP_XOR_MULT_DOSStub_4224 {
  strings:
    $key_4224 = { 16 4c [2] 62 54 [2] 25 56 [2] 62 47 [2] 2c 4b [2] 20 41 [2] 37 4a [2] 2c 04 [2] 11 }

  condition:
    any of them
}