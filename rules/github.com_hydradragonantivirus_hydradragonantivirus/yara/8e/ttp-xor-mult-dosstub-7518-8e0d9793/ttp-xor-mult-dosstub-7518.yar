rule TTP_XOR_MULT_DOSStub_7518 {
  strings:
    $key_7518 = { 21 70 [2] 55 68 [2] 12 6a [2] 55 7b [2] 1b 77 [2] 17 7d [2] 00 76 [2] 1b 38 [2] 26 }

  condition:
    any of them
}