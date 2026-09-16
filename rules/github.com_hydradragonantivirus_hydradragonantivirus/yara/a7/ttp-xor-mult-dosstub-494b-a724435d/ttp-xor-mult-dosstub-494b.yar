rule TTP_XOR_MULT_DOSStub_494b {
  strings:
    $key_494b = { 1d 23 [2] 69 3b [2] 2e 39 [2] 69 28 [2] 27 24 [2] 2b 2e [2] 3c 25 [2] 27 6b [2] 1a }

  condition:
    any of them
}