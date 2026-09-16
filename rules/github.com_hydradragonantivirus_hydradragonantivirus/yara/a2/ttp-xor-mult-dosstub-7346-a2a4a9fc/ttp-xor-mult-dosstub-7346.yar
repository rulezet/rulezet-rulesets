rule TTP_XOR_MULT_DOSStub_7346 {
  strings:
    $key_7346 = { 27 2e [2] 53 36 [2] 14 34 [2] 53 25 [2] 1d 29 [2] 11 23 [2] 06 28 [2] 1d 66 [2] 20 }

  condition:
    any of them
}