rule TTP_XOR_MULT_DOSStub_2345 {
  strings:
    $key_2345 = { 77 2d [2] 03 35 [2] 44 37 [2] 03 26 [2] 4d 2a [2] 41 20 [2] 56 2b [2] 4d 65 [2] 70 }

  condition:
    any of them
}