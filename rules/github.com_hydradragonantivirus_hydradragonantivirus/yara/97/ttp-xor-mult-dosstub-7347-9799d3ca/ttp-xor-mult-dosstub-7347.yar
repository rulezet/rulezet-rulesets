rule TTP_XOR_MULT_DOSStub_7347 {
  strings:
    $key_7347 = { 27 2f [2] 53 37 [2] 14 35 [2] 53 24 [2] 1d 28 [2] 11 22 [2] 06 29 [2] 1d 67 [2] 20 }

  condition:
    any of them
}