rule TTP_XOR_MULT_DOSStub_753d {
  strings:
    $key_753d = { 21 55 [2] 55 4d [2] 12 4f [2] 55 5e [2] 1b 52 [2] 17 58 [2] 00 53 [2] 1b 1d [2] 26 }

  condition:
    any of them
}