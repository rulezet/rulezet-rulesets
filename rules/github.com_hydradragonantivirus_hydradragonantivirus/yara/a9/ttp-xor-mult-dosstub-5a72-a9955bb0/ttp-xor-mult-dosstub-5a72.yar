rule TTP_XOR_MULT_DOSStub_5a72 {
  strings:
    $key_5a72 = { 0e 1a [2] 7a 02 [2] 3d 00 [2] 7a 11 [2] 34 1d [2] 38 17 [2] 2f 1c [2] 34 52 [2] 09 }

  condition:
    any of them
}