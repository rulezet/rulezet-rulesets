rule TTP_XOR_MULT_DOSStub_0e4b {
  strings:
    $key_0e4b = { 5a 23 [2] 2e 3b [2] 69 39 [2] 2e 28 [2] 60 24 [2] 6c 2e [2] 7b 25 [2] 60 6b [2] 5d }

  condition:
    any of them
}