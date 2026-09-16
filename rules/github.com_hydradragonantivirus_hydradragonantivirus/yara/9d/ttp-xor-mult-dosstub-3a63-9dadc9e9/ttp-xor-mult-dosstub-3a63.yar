rule TTP_XOR_MULT_DOSStub_3a63 {
  strings:
    $key_3a63 = { 6e 0b [2] 1a 13 [2] 5d 11 [2] 1a 00 [2] 54 0c [2] 58 06 [2] 4f 0d [2] 54 43 [2] 69 }

  condition:
    any of them
}