rule TTP_XOR_MULT_DOSStub_5d7b {
  strings:
    $key_5d7b = { 09 13 [2] 7d 0b [2] 3a 09 [2] 7d 18 [2] 33 14 [2] 3f 1e [2] 28 15 [2] 33 5b [2] 0e }

  condition:
    any of them
}