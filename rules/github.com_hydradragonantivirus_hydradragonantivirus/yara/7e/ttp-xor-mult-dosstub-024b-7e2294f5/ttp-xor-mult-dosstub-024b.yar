rule TTP_XOR_MULT_DOSStub_024b {
  strings:
    $key_024b = { 56 23 [2] 22 3b [2] 65 39 [2] 22 28 [2] 6c 24 [2] 60 2e [2] 77 25 [2] 6c 6b [2] 51 }

  condition:
    any of them
}