rule TTP_XOR_MULT_DOSStub_2377 {
  strings:
    $key_2377 = { 77 1f [2] 03 07 [2] 44 05 [2] 03 14 [2] 4d 18 [2] 41 12 [2] 56 19 [2] 4d 57 [2] 70 }

  condition:
    any of them
}