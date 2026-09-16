rule TTP_XOR_MULT_DOSStub_5347 {
  strings:
    $key_5347 = { 07 2f [2] 73 37 [2] 34 35 [2] 73 24 [2] 3d 28 [2] 31 22 [2] 26 29 [2] 3d 67 [2] 00 }

  condition:
    any of them
}