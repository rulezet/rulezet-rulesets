rule TTP_XOR_MULT_DOSStub_3a62 {
  strings:
    $key_3a62 = { 6e 0a [2] 1a 12 [2] 5d 10 [2] 1a 01 [2] 54 0d [2] 58 07 [2] 4f 0c [2] 54 42 [2] 69 }

  condition:
    any of them
}