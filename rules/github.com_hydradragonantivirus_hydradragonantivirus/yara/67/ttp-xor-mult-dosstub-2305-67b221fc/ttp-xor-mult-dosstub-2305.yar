rule TTP_XOR_MULT_DOSStub_2305 {
  strings:
    $key_2305 = { 77 6d [2] 03 75 [2] 44 77 [2] 03 66 [2] 4d 6a [2] 41 60 [2] 56 6b [2] 4d 25 [2] 70 }

  condition:
    any of them
}