rule TTP_XOR_MULT_DOSStub_3a56 {
  strings:
    $key_3a56 = { 6e 3e [2] 1a 26 [2] 5d 24 [2] 1a 35 [2] 54 39 [2] 58 33 [2] 4f 38 [2] 54 76 [2] 69 }

  condition:
    any of them
}