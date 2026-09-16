rule TTP_XOR_MULT_DOSStub_4a7b {
  strings:
    $key_4a7b = { 1e 13 [2] 6a 0b [2] 2d 09 [2] 6a 18 [2] 24 14 [2] 28 1e [2] 3f 15 [2] 24 5b [2] 19 }

  condition:
    any of them
}