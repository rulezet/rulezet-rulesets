rule TTP_XOR_MULT_DOSStub_7515 {
  strings:
    $key_7515 = { 21 7d [2] 55 65 [2] 12 67 [2] 55 76 [2] 1b 7a [2] 17 70 [2] 00 7b [2] 1b 35 [2] 26 }

  condition:
    any of them
}