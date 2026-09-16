rule TTP_XOR_MULT_DOSStub_354b {
  strings:
    $key_354b = { 61 23 [2] 15 3b [2] 52 39 [2] 15 28 [2] 5b 24 [2] 57 2e [2] 40 25 [2] 5b 6b [2] 66 }

  condition:
    any of them
}