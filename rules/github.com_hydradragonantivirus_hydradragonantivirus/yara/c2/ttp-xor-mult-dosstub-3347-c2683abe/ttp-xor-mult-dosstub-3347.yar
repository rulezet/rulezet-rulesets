rule TTP_XOR_MULT_DOSStub_3347 {
  strings:
    $key_3347 = { 67 2f [2] 13 37 [2] 54 35 [2] 13 24 [2] 5d 28 [2] 51 22 [2] 46 29 [2] 5d 67 [2] 60 }

  condition:
    any of them
}