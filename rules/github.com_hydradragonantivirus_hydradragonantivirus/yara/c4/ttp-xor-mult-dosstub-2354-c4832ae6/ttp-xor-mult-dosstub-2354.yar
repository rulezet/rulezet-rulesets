rule TTP_XOR_MULT_DOSStub_2354 {
  strings:
    $key_2354 = { 77 3c [2] 03 24 [2] 44 26 [2] 03 37 [2] 4d 3b [2] 41 31 [2] 56 3a [2] 4d 74 [2] 70 }

  condition:
    any of them
}