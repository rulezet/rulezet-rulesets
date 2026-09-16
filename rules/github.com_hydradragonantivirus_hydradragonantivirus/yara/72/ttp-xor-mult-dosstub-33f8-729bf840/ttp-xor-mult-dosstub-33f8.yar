rule TTP_XOR_MULT_DOSStub_33f8 {
  strings:
    $key_33f8 = { 67 90 [2] 13 88 [2] 54 8a [2] 13 9b [2] 5d 97 [2] 51 9d [2] 46 96 [2] 5d d8 [2] 60 }

  condition:
    any of them
}