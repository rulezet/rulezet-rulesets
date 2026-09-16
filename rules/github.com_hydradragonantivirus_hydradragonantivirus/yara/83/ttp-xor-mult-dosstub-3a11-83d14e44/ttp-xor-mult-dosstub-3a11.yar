rule TTP_XOR_MULT_DOSStub_3a11 {
  strings:
    $key_3a11 = { 6e 79 [2] 1a 61 [2] 5d 63 [2] 1a 72 [2] 54 7e [2] 58 74 [2] 4f 7f [2] 54 31 [2] 69 }

  condition:
    any of them
}