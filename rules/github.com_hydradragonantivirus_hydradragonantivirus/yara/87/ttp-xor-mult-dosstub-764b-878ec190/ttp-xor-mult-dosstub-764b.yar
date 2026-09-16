rule TTP_XOR_MULT_DOSStub_764b {
  strings:
    $key_764b = { 22 23 [2] 56 3b [2] 11 39 [2] 56 28 [2] 18 24 [2] 14 2e [2] 03 25 [2] 18 6b [2] 25 }

  condition:
    any of them
}