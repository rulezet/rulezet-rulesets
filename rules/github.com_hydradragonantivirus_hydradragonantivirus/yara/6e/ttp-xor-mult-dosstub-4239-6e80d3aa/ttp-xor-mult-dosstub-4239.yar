rule TTP_XOR_MULT_DOSStub_4239 {
  strings:
    $key_4239 = { 16 51 [2] 62 49 [2] 25 4b [2] 62 5a [2] 2c 56 [2] 20 5c [2] 37 57 [2] 2c 19 [2] 11 }

  condition:
    any of them
}