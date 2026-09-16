rule TTP_XOR_MULT_DOSStub_4259 {
  strings:
    $key_4259 = { 16 31 [2] 62 29 [2] 25 2b [2] 62 3a [2] 2c 36 [2] 20 3c [2] 37 37 [2] 2c 79 [2] 11 }

  condition:
    any of them
}