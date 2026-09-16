rule TTP_XOR_MULT_DOSStub_4336 {
  strings:
    $key_4336 = { 17 5e [2] 63 46 [2] 24 44 [2] 63 55 [2] 2d 59 [2] 21 53 [2] 36 58 [2] 2d 16 [2] 10 }

  condition:
    any of them
}