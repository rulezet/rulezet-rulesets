rule TTP_XOR_MULT_DOSStub_5d4b {
  strings:
    $key_5d4b = { 09 23 [2] 7d 3b [2] 3a 39 [2] 7d 28 [2] 33 24 [2] 3f 2e [2] 28 25 [2] 33 6b [2] 0e }

  condition:
    any of them
}