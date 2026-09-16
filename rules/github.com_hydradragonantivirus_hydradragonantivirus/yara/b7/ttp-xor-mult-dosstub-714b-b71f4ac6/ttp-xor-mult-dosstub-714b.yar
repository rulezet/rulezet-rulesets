rule TTP_XOR_MULT_DOSStub_714b {
  strings:
    $key_714b = { 25 23 [2] 51 3b [2] 16 39 [2] 51 28 [2] 1f 24 [2] 13 2e [2] 04 25 [2] 1f 6b [2] 22 }

  condition:
    any of them
}