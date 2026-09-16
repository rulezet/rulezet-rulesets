rule TTP_XOR_MULT_DOSStub_3a46 {
  strings:
    $key_3a46 = { 6e 2e [2] 1a 36 [2] 5d 34 [2] 1a 25 [2] 54 29 [2] 58 23 [2] 4f 28 [2] 54 66 [2] 69 }

  condition:
    any of them
}