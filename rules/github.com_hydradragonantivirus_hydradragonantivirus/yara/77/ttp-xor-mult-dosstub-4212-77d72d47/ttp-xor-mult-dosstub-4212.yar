rule TTP_XOR_MULT_DOSStub_4212 {
  strings:
    $key_4212 = { 16 7a [2] 62 62 [2] 25 60 [2] 62 71 [2] 2c 7d [2] 20 77 [2] 37 7c [2] 2c 32 [2] 11 }

  condition:
    any of them
}