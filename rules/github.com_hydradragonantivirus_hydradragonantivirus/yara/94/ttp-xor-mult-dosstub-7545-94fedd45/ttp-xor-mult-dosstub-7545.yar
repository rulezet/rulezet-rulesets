rule TTP_XOR_MULT_DOSStub_7545 {
  strings:
    $key_7545 = { 21 2d [2] 55 35 [2] 12 37 [2] 55 26 [2] 1b 2a [2] 17 20 [2] 00 2b [2] 1b 65 [2] 26 }

  condition:
    any of them
}