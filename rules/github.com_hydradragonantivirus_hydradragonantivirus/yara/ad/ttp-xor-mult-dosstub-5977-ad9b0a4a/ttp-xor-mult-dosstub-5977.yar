rule TTP_XOR_MULT_DOSStub_5977 {
  strings:
    $key_5977 = { 0d 1f [2] 79 07 [2] 3e 05 [2] 79 14 [2] 37 18 [2] 3b 12 [2] 2c 19 [2] 37 57 [2] 0a }

  condition:
    any of them
}