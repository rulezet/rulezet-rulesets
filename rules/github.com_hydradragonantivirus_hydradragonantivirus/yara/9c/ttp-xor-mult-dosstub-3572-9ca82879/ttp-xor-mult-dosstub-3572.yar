rule TTP_XOR_MULT_DOSStub_3572 {
  strings:
    $key_3572 = { 61 1a [2] 15 02 [2] 52 00 [2] 15 11 [2] 5b 1d [2] 57 17 [2] 40 1c [2] 5b 52 [2] 66 }

  condition:
    any of them
}