rule TTP_XOR_MULT_DOSStub_5478 {
  strings:
    $key_5478 = { 00 10 [2] 74 08 [2] 33 0a [2] 74 1b [2] 3a 17 [2] 36 1d [2] 21 16 [2] 3a 58 [2] 07 }

  condition:
    any of them
}