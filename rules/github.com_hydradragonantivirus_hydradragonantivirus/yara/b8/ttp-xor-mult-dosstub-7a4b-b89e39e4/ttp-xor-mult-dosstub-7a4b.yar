rule TTP_XOR_MULT_DOSStub_7a4b {
  strings:
    $key_7a4b = { 2e 23 [2] 5a 3b [2] 1d 39 [2] 5a 28 [2] 14 24 [2] 18 2e [2] 0f 25 [2] 14 6b [2] 29 }

  condition:
    any of them
}