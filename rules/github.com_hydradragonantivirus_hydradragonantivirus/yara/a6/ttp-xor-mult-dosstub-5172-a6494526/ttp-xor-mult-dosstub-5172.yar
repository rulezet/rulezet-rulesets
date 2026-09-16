rule TTP_XOR_MULT_DOSStub_5172 {
  strings:
    $key_5172 = { 05 1a [2] 71 02 [2] 36 00 [2] 71 11 [2] 3f 1d [2] 33 17 [2] 24 1c [2] 3f 52 [2] 02 }

  condition:
    any of them
}