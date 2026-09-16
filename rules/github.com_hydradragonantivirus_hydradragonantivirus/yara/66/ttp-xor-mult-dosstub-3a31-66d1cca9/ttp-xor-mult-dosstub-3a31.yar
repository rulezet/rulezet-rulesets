rule TTP_XOR_MULT_DOSStub_3a31 {
  strings:
    $key_3a31 = { 6e 59 [2] 1a 41 [2] 5d 43 [2] 1a 52 [2] 54 5e [2] 58 54 [2] 4f 5f [2] 54 11 [2] 69 }

  condition:
    any of them
}