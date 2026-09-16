rule TTP_XOR_MULT_DOSStub_5432 {
  strings:
    $key_5432 = { 00 5a [2] 74 42 [2] 33 40 [2] 74 51 [2] 3a 5d [2] 36 57 [2] 21 5c [2] 3a 12 [2] 07 }

  condition:
    any of them
}