rule TTP_XOR_MULT_DOSStub_4352 {
  strings:
    $key_4352 = { 17 3a [2] 63 22 [2] 24 20 [2] 63 31 [2] 2d 3d [2] 21 37 [2] 36 3c [2] 2d 72 [2] 10 }

  condition:
    any of them
}