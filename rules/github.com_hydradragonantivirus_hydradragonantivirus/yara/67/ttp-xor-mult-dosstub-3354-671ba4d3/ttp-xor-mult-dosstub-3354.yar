rule TTP_XOR_MULT_DOSStub_3354 {
  strings:
    $key_3354 = { 67 3c [2] 13 24 [2] 54 26 [2] 13 37 [2] 5d 3b [2] 51 31 [2] 46 3a [2] 5d 74 [2] 60 }

  condition:
    any of them
}