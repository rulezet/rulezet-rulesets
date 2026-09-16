rule TTP_XOR_MULT_DOSStub_3a26 {
  strings:
    $key_3a26 = { 6e 4e [2] 1a 56 [2] 5d 54 [2] 1a 45 [2] 54 49 [2] 58 43 [2] 4f 48 [2] 54 06 [2] 69 }

  condition:
    any of them
}