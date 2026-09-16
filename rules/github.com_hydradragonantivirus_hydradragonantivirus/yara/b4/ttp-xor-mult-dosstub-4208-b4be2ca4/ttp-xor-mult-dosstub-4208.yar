rule TTP_XOR_MULT_DOSStub_4208 {
  strings:
    $key_4208 = { 16 60 [2] 62 78 [2] 25 7a [2] 62 6b [2] 2c 67 [2] 20 6d [2] 37 66 [2] 2c 28 [2] 11 }

  condition:
    any of them
}