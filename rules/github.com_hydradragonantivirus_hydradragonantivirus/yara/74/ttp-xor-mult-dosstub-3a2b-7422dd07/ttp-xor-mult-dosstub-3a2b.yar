rule TTP_XOR_MULT_DOSStub_3a2b {
  strings:
    $key_3a2b = { 6e 43 [2] 1a 5b [2] 5d 59 [2] 1a 48 [2] 54 44 [2] 58 4e [2] 4f 45 [2] 54 0b [2] 69 }

  condition:
    any of them
}