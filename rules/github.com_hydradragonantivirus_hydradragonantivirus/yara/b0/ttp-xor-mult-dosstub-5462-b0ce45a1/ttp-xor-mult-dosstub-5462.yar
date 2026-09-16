rule TTP_XOR_MULT_DOSStub_5462 {
  strings:
    $key_5462 = { 00 0a [2] 74 12 [2] 33 10 [2] 74 01 [2] 3a 0d [2] 36 07 [2] 21 0c [2] 3a 42 [2] 07 }

  condition:
    any of them
}