rule TTP_XOR_MULT_DOSStub_3a3b {
  strings:
    $key_3a3b = { 6e 53 [2] 1a 4b [2] 5d 49 [2] 1a 58 [2] 54 54 [2] 58 5e [2] 4f 55 [2] 54 1b [2] 69 }

  condition:
    any of them
}