rule TTP_XOR_MULT_DOSStub_700b {
  strings:
    $key_700b = { 24 63 [2] 50 7b [2] 17 79 [2] 50 68 [2] 1e 64 [2] 12 6e [2] 05 65 [2] 1e 2b [2] 23 }

  condition:
    any of them
}