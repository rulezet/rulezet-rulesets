rule TTP_XOR_MULT_DOSStub_547b {
  strings:
    $key_547b = { 00 13 [2] 74 0b [2] 33 09 [2] 74 18 [2] 3a 14 [2] 36 1e [2] 21 15 [2] 3a 5b [2] 07 }

  condition:
    any of them
}