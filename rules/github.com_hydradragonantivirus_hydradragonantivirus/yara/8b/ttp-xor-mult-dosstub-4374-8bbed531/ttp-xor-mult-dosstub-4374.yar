rule TTP_XOR_MULT_DOSStub_4374 {
  strings:
    $key_4374 = { 17 1c [2] 63 04 [2] 24 06 [2] 63 17 [2] 2d 1b [2] 21 11 [2] 36 1a [2] 2d 54 [2] 10 }

  condition:
    any of them
}