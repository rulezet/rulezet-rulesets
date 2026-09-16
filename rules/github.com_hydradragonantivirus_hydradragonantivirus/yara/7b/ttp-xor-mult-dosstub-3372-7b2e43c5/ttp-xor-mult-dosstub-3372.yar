rule TTP_XOR_MULT_DOSStub_3372 {
  strings:
    $key_3372 = { 67 1a [2] 13 02 [2] 54 00 [2] 13 11 [2] 5d 1d [2] 51 17 [2] 46 1c [2] 5d 52 [2] 60 }

  condition:
    any of them
}