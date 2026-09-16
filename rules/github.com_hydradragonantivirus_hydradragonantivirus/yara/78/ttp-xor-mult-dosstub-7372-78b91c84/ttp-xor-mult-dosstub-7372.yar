rule TTP_XOR_MULT_DOSStub_7372 {
  strings:
    $key_7372 = { 27 1a [2] 53 02 [2] 14 00 [2] 53 11 [2] 1d 1d [2] 11 17 [2] 06 1c [2] 1d 52 [2] 20 }

  condition:
    any of them
}