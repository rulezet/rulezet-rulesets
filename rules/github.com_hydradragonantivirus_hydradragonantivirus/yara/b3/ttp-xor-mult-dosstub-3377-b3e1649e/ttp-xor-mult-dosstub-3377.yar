rule TTP_XOR_MULT_DOSStub_3377 {
  strings:
    $key_3377 = { 67 1f [2] 13 07 [2] 54 05 [2] 13 14 [2] 5d 18 [2] 51 12 [2] 46 19 [2] 5d 57 [2] 60 }

  condition:
    any of them
}