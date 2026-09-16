rule TTP_XOR_MULT_DOSStub_007b {
  strings:
    $key_007b = { 54 13 [2] 20 0b [2] 67 09 [2] 20 18 [2] 6e 14 [2] 62 1e [2] 75 15 [2] 6e 5b [2] 53 }

  condition:
    any of them
}