rule TTP_XOR_MULT_DOSStub_5459 {
  strings:
    $key_5459 = { 00 31 [2] 74 29 [2] 33 2b [2] 74 3a [2] 3a 36 [2] 36 3c [2] 21 37 [2] 3a 79 [2] 07 }

  condition:
    any of them
}