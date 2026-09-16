rule TTP_XOR_MULT_DOSStub_2374 {
  strings:
    $key_2374 = { 77 1c [2] 03 04 [2] 44 06 [2] 03 17 [2] 4d 1b [2] 41 11 [2] 56 1a [2] 4d 54 [2] 70 }

  condition:
    any of them
}