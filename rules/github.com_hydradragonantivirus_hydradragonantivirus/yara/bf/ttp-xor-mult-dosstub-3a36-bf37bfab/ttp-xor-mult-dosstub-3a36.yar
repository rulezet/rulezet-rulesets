rule TTP_XOR_MULT_DOSStub_3a36 {
  strings:
    $key_3a36 = { 6e 5e [2] 1a 46 [2] 5d 44 [2] 1a 55 [2] 54 59 [2] 58 53 [2] 4f 58 [2] 54 16 [2] 69 }

  condition:
    any of them
}