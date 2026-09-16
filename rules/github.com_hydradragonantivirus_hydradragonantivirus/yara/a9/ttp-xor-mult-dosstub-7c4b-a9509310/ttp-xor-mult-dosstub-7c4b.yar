rule TTP_XOR_MULT_DOSStub_7c4b {
  strings:
    $key_7c4b = { 28 23 [2] 5c 3b [2] 1b 39 [2] 5c 28 [2] 12 24 [2] 1e 2e [2] 09 25 [2] 12 6b [2] 2f }

  condition:
    any of them
}