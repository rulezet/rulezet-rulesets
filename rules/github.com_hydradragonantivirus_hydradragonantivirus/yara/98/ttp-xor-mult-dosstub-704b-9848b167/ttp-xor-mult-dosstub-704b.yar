rule TTP_XOR_MULT_DOSStub_704b {
  strings:
    $key_704b = { 24 23 [2] 50 3b [2] 17 39 [2] 50 28 [2] 1e 24 [2] 12 2e [2] 05 25 [2] 1e 6b [2] 23 }

  condition:
    any of them
}