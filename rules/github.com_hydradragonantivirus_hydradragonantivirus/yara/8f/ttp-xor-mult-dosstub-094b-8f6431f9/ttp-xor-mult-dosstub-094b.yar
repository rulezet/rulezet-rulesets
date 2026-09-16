rule TTP_XOR_MULT_DOSStub_094b {
  strings:
    $key_094b = { 5d 23 [2] 29 3b [2] 6e 39 [2] 29 28 [2] 67 24 [2] 6b 2e [2] 7c 25 [2] 67 6b [2] 5a }

  condition:
    any of them
}