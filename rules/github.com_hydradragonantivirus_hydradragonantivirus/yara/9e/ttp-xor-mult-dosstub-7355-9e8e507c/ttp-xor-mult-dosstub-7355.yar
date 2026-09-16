rule TTP_XOR_MULT_DOSStub_7355 {
  strings:
    $key_7355 = { 27 3d [2] 53 25 [2] 14 27 [2] 53 36 [2] 1d 3a [2] 11 30 [2] 06 3b [2] 1d 75 [2] 20 }

  condition:
    any of them
}