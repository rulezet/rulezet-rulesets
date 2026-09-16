rule TTP_XOR_MULT_DOSStub_4359 {
  strings:
    $key_4359 = { 17 31 [2] 63 29 [2] 24 2b [2] 63 3a [2] 2d 36 [2] 21 3c [2] 36 37 [2] 2d 79 [2] 10 }

  condition:
    any of them
}