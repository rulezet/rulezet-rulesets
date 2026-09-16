rule TTP_XOR_MULT_DOSStub_0372 {
  strings:
    $key_0372 = { 57 1a [2] 23 02 [2] 64 00 [2] 23 11 [2] 6d 1d [2] 61 17 [2] 76 1c [2] 6d 52 [2] 50 }

  condition:
    any of them
}