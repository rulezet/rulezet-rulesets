rule TTP_XOR_MULT_DOSStub_3672 {
  strings:
    $key_3672 = { 62 1a [2] 16 02 [2] 51 00 [2] 16 11 [2] 58 1d [2] 54 17 [2] 43 1c [2] 58 52 [2] 65 }

  condition:
    any of them
}