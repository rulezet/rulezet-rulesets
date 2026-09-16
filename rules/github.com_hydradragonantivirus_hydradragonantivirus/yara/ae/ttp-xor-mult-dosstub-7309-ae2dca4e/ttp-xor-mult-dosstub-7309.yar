rule TTP_XOR_MULT_DOSStub_7309 {
  strings:
    $key_7309 = { 27 61 [2] 53 79 [2] 14 7b [2] 53 6a [2] 1d 66 [2] 11 6c [2] 06 67 [2] 1d 29 [2] 20 }

  condition:
    any of them
}