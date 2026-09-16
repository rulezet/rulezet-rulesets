rule TTP_XOR_MULT_DOSStub_3a47 {
  strings:
    $key_3a47 = { 6e 2f [2] 1a 37 [2] 5d 35 [2] 1a 24 [2] 54 28 [2] 58 22 [2] 4f 29 [2] 54 67 [2] 69 }

  condition:
    any of them
}