rule TTP_XOR_MULT_DOSStub_33f4 {
  strings:
    $key_33f4 = { 67 9c [2] 13 84 [2] 54 86 [2] 13 97 [2] 5d 9b [2] 51 91 [2] 46 9a [2] 5d d4 [2] 60 }

  condition:
    any of them
}