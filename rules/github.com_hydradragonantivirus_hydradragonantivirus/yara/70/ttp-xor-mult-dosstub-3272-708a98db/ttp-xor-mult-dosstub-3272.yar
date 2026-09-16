rule TTP_XOR_MULT_DOSStub_3272 {
  strings:
    $key_3272 = { 66 1a [2] 12 02 [2] 55 00 [2] 12 11 [2] 5c 1d [2] 50 17 [2] 47 1c [2] 5c 52 [2] 61 }

  condition:
    any of them
}