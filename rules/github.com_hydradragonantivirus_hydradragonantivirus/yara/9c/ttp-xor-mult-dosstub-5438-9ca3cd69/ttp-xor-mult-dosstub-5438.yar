rule TTP_XOR_MULT_DOSStub_5438 {
  strings:
    $key_5438 = { 00 50 [2] 74 48 [2] 33 4a [2] 74 5b [2] 3a 57 [2] 36 5d [2] 21 56 [2] 3a 18 [2] 07 }

  condition:
    any of them
}