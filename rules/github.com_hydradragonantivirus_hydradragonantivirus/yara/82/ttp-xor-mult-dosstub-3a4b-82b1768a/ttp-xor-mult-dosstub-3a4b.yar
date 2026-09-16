rule TTP_XOR_MULT_DOSStub_3a4b {
  strings:
    $key_3a4b = { 6e 23 [2] 1a 3b [2] 5d 39 [2] 1a 28 [2] 54 24 [2] 58 2e [2] 4f 25 [2] 54 6b [2] 69 }

  condition:
    any of them
}