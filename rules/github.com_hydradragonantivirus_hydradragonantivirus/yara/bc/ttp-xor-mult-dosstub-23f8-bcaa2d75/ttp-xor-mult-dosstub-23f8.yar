rule TTP_XOR_MULT_DOSStub_23f8 {
  strings:
    $key_23f8 = { 77 90 [2] 03 88 [2] 44 8a [2] 03 9b [2] 4d 97 [2] 41 9d [2] 56 96 [2] 4d d8 [2] 70 }

  condition:
    any of them
}