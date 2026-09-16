rule TTP_XOR_MULT_DOSStub_3349 {
  strings:
    $key_3349 = { 67 21 [2] 13 39 [2] 54 3b [2] 13 2a [2] 5d 26 [2] 51 2c [2] 46 27 [2] 5d 69 [2] 60 }

  condition:
    any of them
}