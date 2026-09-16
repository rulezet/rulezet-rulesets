rule TTP_XOR_MULT_DOSStub_047b {
  strings:
    $key_047b = { 50 13 [2] 24 0b [2] 63 09 [2] 24 18 [2] 6a 14 [2] 66 1e [2] 71 15 [2] 6a 5b [2] 57 }

  condition:
    any of them
}