rule TTP_XOR_MULT_DOSStub_4d4b {
  strings:
    $key_4d4b = { 19 23 [2] 6d 3b [2] 2a 39 [2] 6d 28 [2] 23 24 [2] 2f 2e [2] 38 25 [2] 23 6b [2] 1e }

  condition:
    any of them
}