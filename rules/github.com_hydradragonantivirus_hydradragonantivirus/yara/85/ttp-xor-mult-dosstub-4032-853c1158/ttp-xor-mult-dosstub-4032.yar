rule TTP_XOR_MULT_DOSStub_4032 {
  strings:
    $key_4032 = { 14 5a [2] 60 42 [2] 27 40 [2] 60 51 [2] 2e 5d [2] 22 57 [2] 35 5c [2] 2e 12 [2] 13 }

  condition:
    any of them
}