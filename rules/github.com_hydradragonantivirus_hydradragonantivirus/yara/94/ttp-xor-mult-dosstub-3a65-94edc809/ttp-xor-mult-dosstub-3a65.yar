rule TTP_XOR_MULT_DOSStub_3a65 {
  strings:
    $key_3a65 = { 6e 0d [2] 1a 15 [2] 5d 17 [2] 1a 06 [2] 54 0a [2] 58 00 [2] 4f 0b [2] 54 45 [2] 69 }

  condition:
    any of them
}