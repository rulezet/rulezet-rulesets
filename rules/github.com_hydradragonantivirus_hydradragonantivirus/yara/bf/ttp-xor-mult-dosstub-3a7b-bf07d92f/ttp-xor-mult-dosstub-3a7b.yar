rule TTP_XOR_MULT_DOSStub_3a7b {
  strings:
    $key_3a7b = { 6e 13 [2] 1a 0b [2] 5d 09 [2] 1a 18 [2] 54 14 [2] 58 1e [2] 4f 15 [2] 54 5b [2] 69 }

  condition:
    any of them
}