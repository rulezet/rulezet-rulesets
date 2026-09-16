rule TTP_XOR_MULT_DOSStub_4233 {
  strings:
    $key_4233 = { 16 5b [2] 62 43 [2] 25 41 [2] 62 50 [2] 2c 5c [2] 20 56 [2] 37 5d [2] 2c 13 [2] 11 }

  condition:
    any of them
}