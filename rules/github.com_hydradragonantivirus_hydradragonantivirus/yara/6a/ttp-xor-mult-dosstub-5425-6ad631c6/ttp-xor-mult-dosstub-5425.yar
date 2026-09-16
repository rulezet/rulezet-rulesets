rule TTP_XOR_MULT_DOSStub_5425 {
  strings:
    $key_5425 = { 00 4d [2] 74 55 [2] 33 57 [2] 74 46 [2] 3a 4a [2] 36 40 [2] 21 4b [2] 3a 05 [2] 07 }

  condition:
    any of them
}