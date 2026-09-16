rule TTP_XOR_MULT_DOSStub_5470 {
  strings:
    $key_5470 = { 00 18 [2] 74 00 [2] 33 02 [2] 74 13 [2] 3a 1f [2] 36 15 [2] 21 1e [2] 3a 50 [2] 07 }

  condition:
    any of them
}