rule TTP_XOR_MULT_DOSStub_2348 {
  strings:
    $key_2348 = { 77 20 [2] 03 38 [2] 44 3a [2] 03 2b [2] 4d 27 [2] 41 2d [2] 56 26 [2] 4d 68 [2] 70 }

  condition:
    any of them
}