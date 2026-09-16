rule TTP_XOR_MULT_DOSStub_3a27 {
  strings:
    $key_3a27 = { 6e 4f [2] 1a 57 [2] 5d 55 [2] 1a 44 [2] 54 48 [2] 58 42 [2] 4f 49 [2] 54 07 [2] 69 }

  condition:
    any of them
}