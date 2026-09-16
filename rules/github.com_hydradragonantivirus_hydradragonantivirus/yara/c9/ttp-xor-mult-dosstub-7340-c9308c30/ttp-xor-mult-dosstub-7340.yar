rule TTP_XOR_MULT_DOSStub_7340 {
  strings:
    $key_7340 = { 27 28 [2] 53 30 [2] 14 32 [2] 53 23 [2] 1d 2f [2] 11 25 [2] 06 2e [2] 1d 60 [2] 20 }

  condition:
    any of them
}