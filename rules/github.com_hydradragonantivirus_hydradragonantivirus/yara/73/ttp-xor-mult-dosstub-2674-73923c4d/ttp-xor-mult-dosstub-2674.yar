rule TTP_XOR_MULT_DOSStub_2674 {
  strings:
    $key_2674 = { 72 1c [2] 06 04 [2] 41 06 [2] 06 17 [2] 48 1b [2] 44 11 [2] 53 1a [2] 48 54 [2] 75 }

  condition:
    any of them
}