rule TTP_XOR_MULT_DOSStub_2272 {
  strings:
    $key_2272 = { 76 1a [2] 02 02 [2] 45 00 [2] 02 11 [2] 4c 1d [2] 40 17 [2] 57 1c [2] 4c 52 [2] 71 }

  condition:
    any of them
}