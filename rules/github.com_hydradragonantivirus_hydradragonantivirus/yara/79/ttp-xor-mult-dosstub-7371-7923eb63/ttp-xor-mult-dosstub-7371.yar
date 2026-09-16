rule TTP_XOR_MULT_DOSStub_7371 {
  strings:
    $key_7371 = { 27 19 [2] 53 01 [2] 14 03 [2] 53 12 [2] 1d 1e [2] 11 14 [2] 06 1f [2] 1d 51 [2] 20 }

  condition:
    any of them
}