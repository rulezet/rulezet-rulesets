rule TTP_XOR_MULT_DOSStub_244b {
  strings:
    $key_244b = { 70 23 [2] 04 3b [2] 43 39 [2] 04 28 [2] 4a 24 [2] 46 2e [2] 51 25 [2] 4a 6b [2] 77 }

  condition:
    any of them
}