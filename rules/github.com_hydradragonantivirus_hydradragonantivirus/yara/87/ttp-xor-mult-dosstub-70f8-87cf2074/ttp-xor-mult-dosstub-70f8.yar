rule TTP_XOR_MULT_DOSStub_70f8 {
  strings:
    $key_70f8 = { 24 90 [2] 50 88 [2] 17 8a [2] 50 9b [2] 1e 97 [2] 12 9d [2] 05 96 [2] 1e d8 [2] 23 }

  condition:
    any of them
}