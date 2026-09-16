rule TTP_XOR_MULT_DOSStub_4355 {
  strings:
    $key_4355 = { 17 3d [2] 63 25 [2] 24 27 [2] 63 36 [2] 2d 3a [2] 21 30 [2] 36 3b [2] 2d 75 [2] 10 }

  condition:
    any of them
}