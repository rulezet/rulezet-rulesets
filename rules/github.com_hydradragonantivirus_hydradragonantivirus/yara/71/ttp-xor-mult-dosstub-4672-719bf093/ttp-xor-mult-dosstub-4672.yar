rule TTP_XOR_MULT_DOSStub_4672 {
  strings:
    $key_4672 = { 12 1a [2] 66 02 [2] 21 00 [2] 66 11 [2] 28 1d [2] 24 17 [2] 33 1c [2] 28 52 [2] 15 }

  condition:
    any of them
}