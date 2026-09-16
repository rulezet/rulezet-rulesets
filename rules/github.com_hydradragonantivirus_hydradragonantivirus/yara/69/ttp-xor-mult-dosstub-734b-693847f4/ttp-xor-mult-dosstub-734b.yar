rule TTP_XOR_MULT_DOSStub_734b {
  strings:
    $key_734b = { 27 23 [2] 53 3b [2] 14 39 [2] 53 28 [2] 1d 24 [2] 11 2e [2] 06 25 [2] 1d 6b [2] 20 }

  condition:
    any of them
}