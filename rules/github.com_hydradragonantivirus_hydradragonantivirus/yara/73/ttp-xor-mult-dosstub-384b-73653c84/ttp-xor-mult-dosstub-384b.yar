rule TTP_XOR_MULT_DOSStub_384b {
  strings:
    $key_384b = { 6c 23 [2] 18 3b [2] 5f 39 [2] 18 28 [2] 56 24 [2] 5a 2e [2] 4d 25 [2] 56 6b [2] 6b }

  condition:
    any of them
}