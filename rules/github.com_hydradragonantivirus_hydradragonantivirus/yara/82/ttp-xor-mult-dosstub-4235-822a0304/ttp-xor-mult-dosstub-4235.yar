rule TTP_XOR_MULT_DOSStub_4235 {
  strings:
    $key_4235 = { 16 5d [2] 62 45 [2] 25 47 [2] 62 56 [2] 2c 5a [2] 20 50 [2] 37 5b [2] 2c 15 [2] 11 }

  condition:
    any of them
}