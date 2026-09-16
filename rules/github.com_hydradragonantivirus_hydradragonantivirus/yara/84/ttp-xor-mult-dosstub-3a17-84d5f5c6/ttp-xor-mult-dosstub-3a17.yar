rule TTP_XOR_MULT_DOSStub_3a17 {
  strings:
    $key_3a17 = { 6e 7f [2] 1a 67 [2] 5d 65 [2] 1a 74 [2] 54 78 [2] 58 72 [2] 4f 79 [2] 54 37 [2] 69 }

  condition:
    any of them
}