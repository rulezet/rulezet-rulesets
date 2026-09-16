rule TTP_XOR_MULT_DOSStub_4347 {
  strings:
    $key_4347 = { 17 2f [2] 63 37 [2] 24 35 [2] 63 24 [2] 2d 28 [2] 21 22 [2] 36 29 [2] 2d 67 [2] 10 }

  condition:
    any of them
}