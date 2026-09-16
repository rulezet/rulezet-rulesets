rule TTP_XOR_MULT_DOSStub_7447 {
  strings:
    $key_7447 = { 20 2f [2] 54 37 [2] 13 35 [2] 54 24 [2] 1a 28 [2] 16 22 [2] 01 29 [2] 1a 67 [2] 27 }

  condition:
    any of them
}