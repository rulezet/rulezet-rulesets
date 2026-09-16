rule TTP_XOR_MULT_DOSStub_7320 {
  strings:
    $key_7320 = { 27 48 [2] 53 50 [2] 14 52 [2] 53 43 [2] 1d 4f [2] 11 45 [2] 06 4e [2] 1d 00 [2] 20 }

  condition:
    any of them
}