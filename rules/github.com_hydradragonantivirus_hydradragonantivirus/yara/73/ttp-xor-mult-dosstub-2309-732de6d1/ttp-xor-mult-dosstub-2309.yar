rule TTP_XOR_MULT_DOSStub_2309 {
  strings:
    $key_2309 = { 77 61 [2] 03 79 [2] 44 7b [2] 03 6a [2] 4d 66 [2] 41 6c [2] 56 67 [2] 4d 29 [2] 70 }

  condition:
    any of them
}