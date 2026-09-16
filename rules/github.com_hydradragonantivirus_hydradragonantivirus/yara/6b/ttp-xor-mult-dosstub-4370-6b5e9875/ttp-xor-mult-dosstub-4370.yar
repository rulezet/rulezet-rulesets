rule TTP_XOR_MULT_DOSStub_4370 {
  strings:
    $key_4370 = { 17 18 [2] 63 00 [2] 24 02 [2] 63 13 [2] 2d 1f [2] 21 15 [2] 36 1e [2] 2d 50 [2] 10 }

  condition:
    any of them
}