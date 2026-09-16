rule TTP_XOR_MULT_DOSStub_2032 {
  strings:
    $key_2032 = { 74 5a [2] 00 42 [2] 47 40 [2] 00 51 [2] 4e 5d [2] 42 57 [2] 55 5c [2] 4e 12 [2] 73 }

  condition:
    any of them
}