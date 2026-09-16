rule TTP_XOR_MULT_DOSStub_444b {
  strings:
    $key_444b = { 10 23 [2] 64 3b [2] 23 39 [2] 64 28 [2] 2a 24 [2] 26 2e [2] 31 25 [2] 2a 6b [2] 17 }

  condition:
    any of them
}