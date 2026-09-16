rule TTP_XOR_MULT_DOSStub_7560 {
  strings:
    $key_7560 = { 21 08 [2] 55 10 [2] 12 12 [2] 55 03 [2] 1b 0f [2] 17 05 [2] 00 0e [2] 1b 40 [2] 26 }

  condition:
    any of them
}