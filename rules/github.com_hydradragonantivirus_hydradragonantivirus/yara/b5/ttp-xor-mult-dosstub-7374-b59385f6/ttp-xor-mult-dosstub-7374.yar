rule TTP_XOR_MULT_DOSStub_7374 {
  strings:
    $key_7374 = { 27 1c [2] 53 04 [2] 14 06 [2] 53 17 [2] 1d 1b [2] 11 11 [2] 06 1a [2] 1d 54 [2] 20 }

  condition:
    any of them
}