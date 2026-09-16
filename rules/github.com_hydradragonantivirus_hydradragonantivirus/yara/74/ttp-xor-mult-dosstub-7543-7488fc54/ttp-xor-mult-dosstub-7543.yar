rule TTP_XOR_MULT_DOSStub_7543 {
  strings:
    $key_7543 = { 21 2b [2] 55 33 [2] 12 31 [2] 55 20 [2] 1b 2c [2] 17 26 [2] 00 2d [2] 1b 63 [2] 26 }

  condition:
    any of them
}