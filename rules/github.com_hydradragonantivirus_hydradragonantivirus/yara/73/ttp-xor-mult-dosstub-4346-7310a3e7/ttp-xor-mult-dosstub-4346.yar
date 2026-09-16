rule TTP_XOR_MULT_DOSStub_4346 {
  strings:
    $key_4346 = { 17 2e [2] 63 36 [2] 24 34 [2] 63 25 [2] 2d 29 [2] 21 23 [2] 36 28 [2] 2d 66 [2] 10 }

  condition:
    any of them
}