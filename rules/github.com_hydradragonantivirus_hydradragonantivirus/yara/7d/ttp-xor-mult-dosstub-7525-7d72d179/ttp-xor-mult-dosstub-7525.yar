rule TTP_XOR_MULT_DOSStub_7525 {
  strings:
    $key_7525 = { 21 4d [2] 55 55 [2] 12 57 [2] 55 46 [2] 1b 4a [2] 17 40 [2] 00 4b [2] 1b 05 [2] 26 }

  condition:
    any of them
}