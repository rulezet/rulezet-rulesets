rule TTP_XOR_MULT_DOSStub_3a7c {
  strings:
    $key_3a7c = { 6e 14 [2] 1a 0c [2] 5d 0e [2] 1a 1f [2] 54 13 [2] 58 19 [2] 4f 12 [2] 54 5c [2] 69 }

  condition:
    any of them
}