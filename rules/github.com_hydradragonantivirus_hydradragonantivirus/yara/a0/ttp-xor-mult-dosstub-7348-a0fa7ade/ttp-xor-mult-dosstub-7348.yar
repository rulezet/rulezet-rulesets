rule TTP_XOR_MULT_DOSStub_7348 {
  strings:
    $key_7348 = { 27 20 [2] 53 38 [2] 14 3a [2] 53 2b [2] 1d 27 [2] 11 2d [2] 06 26 [2] 1d 68 [2] 20 }

  condition:
    any of them
}