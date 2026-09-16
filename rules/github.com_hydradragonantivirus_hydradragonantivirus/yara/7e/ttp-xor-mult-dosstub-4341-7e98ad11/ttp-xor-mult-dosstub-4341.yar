rule TTP_XOR_MULT_DOSStub_4341 {
  strings:
    $key_4341 = { 17 29 [2] 63 31 [2] 24 33 [2] 63 22 [2] 2d 2e [2] 21 24 [2] 36 2f [2] 2d 61 [2] 10 }

  condition:
    any of them
}