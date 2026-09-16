rule TTP_XOR_MULT_DOSStub_1372 {
  strings:
    $key_1372 = { 47 1a [2] 33 02 [2] 74 00 [2] 33 11 [2] 7d 1d [2] 71 17 [2] 66 1c [2] 7d 52 [2] 40 }

  condition:
    any of them
}