rule TTP_XOR_MULT_DOSStub_1a7b {
  strings:
    $key_1a7b = { 4e 13 [2] 3a 0b [2] 7d 09 [2] 3a 18 [2] 74 14 [2] 78 1e [2] 6f 15 [2] 74 5b [2] 49 }

  condition:
    any of them
}