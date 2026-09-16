rule TTP_XOR_MULT_DOSStub_4305 {
  strings:
    $key_4305 = { 17 6d [2] 63 75 [2] 24 77 [2] 63 66 [2] 2d 6a [2] 21 60 [2] 36 6b [2] 2d 25 [2] 10 }

  condition:
    any of them
}