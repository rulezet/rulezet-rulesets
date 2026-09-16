rule TTP_XOR_MULT_DOSStub_4340 {
  strings:
    $key_4340 = { 17 28 [2] 63 30 [2] 24 32 [2] 63 23 [2] 2d 2f [2] 21 25 [2] 36 2e [2] 2d 60 [2] 10 }

  condition:
    any of them
}