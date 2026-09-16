rule TTP_XOR_MULT_DOSStub_414b {
  strings:
    $key_414b = { 15 23 [2] 61 3b [2] 26 39 [2] 61 28 [2] 2f 24 [2] 23 2e [2] 34 25 [2] 2f 6b [2] 12 }

  condition:
    any of them
}