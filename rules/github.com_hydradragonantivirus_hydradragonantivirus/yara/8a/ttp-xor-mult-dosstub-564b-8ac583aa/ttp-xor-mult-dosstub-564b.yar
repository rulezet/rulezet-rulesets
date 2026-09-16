rule TTP_XOR_MULT_DOSStub_564b {
  strings:
    $key_564b = { 02 23 [2] 76 3b [2] 31 39 [2] 76 28 [2] 38 24 [2] 34 2e [2] 23 25 [2] 38 6b [2] 05 }

  condition:
    any of them
}