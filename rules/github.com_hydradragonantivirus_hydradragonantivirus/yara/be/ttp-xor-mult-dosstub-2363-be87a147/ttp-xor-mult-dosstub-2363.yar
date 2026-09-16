rule TTP_XOR_MULT_DOSStub_2363 {
  strings:
    $key_2363 = { 77 0b [2] 03 13 [2] 44 11 [2] 03 00 [2] 4d 0c [2] 41 06 [2] 56 0d [2] 4d 43 [2] 70 }

  condition:
    any of them
}