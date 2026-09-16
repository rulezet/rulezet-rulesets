rule TTP_XOR_MULT_DOSStub_33f9 {
  strings:
    $key_33f9 = { 67 91 [2] 13 89 [2] 54 8b [2] 13 9a [2] 5d 96 [2] 51 9c [2] 46 97 [2] 5d d9 [2] 60 }

  condition:
    any of them
}