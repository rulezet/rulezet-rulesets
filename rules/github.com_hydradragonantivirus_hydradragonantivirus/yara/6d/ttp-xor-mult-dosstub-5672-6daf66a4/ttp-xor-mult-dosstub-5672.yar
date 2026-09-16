rule TTP_XOR_MULT_DOSStub_5672 {
  strings:
    $key_5672 = { 02 1a [2] 76 02 [2] 31 00 [2] 76 11 [2] 38 1d [2] 34 17 [2] 23 1c [2] 38 52 [2] 05 }

  condition:
    any of them
}