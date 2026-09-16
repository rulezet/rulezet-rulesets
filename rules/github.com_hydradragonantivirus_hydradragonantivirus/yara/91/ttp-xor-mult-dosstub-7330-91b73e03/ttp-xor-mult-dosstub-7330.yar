rule TTP_XOR_MULT_DOSStub_7330 {
  strings:
    $key_7330 = { 27 58 [2] 53 40 [2] 14 42 [2] 53 53 [2] 1d 5f [2] 11 55 [2] 06 5e [2] 1d 10 [2] 20 }

  condition:
    any of them
}