rule TTP_XOR_MULT_DOSStub_5422 {
  strings:
    $key_5422 = { 00 4a [2] 74 52 [2] 33 50 [2] 74 41 [2] 3a 4d [2] 36 47 [2] 21 4c [2] 3a 02 [2] 07 }

  condition:
    any of them
}