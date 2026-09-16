rule TTP_XOR_MULT_DOSStub_3359 {
  strings:
    $key_3359 = { 67 31 [2] 13 29 [2] 54 2b [2] 13 3a [2] 5d 36 [2] 51 3c [2] 46 37 [2] 5d 79 [2] 60 }

  condition:
    any of them
}