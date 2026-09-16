rule TTP_XOR_MULT_DOSStub_2369 {
  strings:
    $key_2369 = { 77 01 [2] 03 19 [2] 44 1b [2] 03 0a [2] 4d 06 [2] 41 0c [2] 56 07 [2] 4d 49 [2] 70 }

  condition:
    any of them
}