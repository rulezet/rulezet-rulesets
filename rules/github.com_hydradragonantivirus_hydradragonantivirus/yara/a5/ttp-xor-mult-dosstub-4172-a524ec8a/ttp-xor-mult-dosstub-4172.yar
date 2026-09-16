rule TTP_XOR_MULT_DOSStub_4172 {
  strings:
    $key_4172 = { 15 1a [2] 61 02 [2] 26 00 [2] 61 11 [2] 2f 1d [2] 23 17 [2] 34 1c [2] 2f 52 [2] 12 }

  condition:
    any of them
}