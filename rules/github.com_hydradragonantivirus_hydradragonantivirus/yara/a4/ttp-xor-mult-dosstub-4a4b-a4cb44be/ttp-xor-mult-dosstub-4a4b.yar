rule TTP_XOR_MULT_DOSStub_4a4b {
  strings:
    $key_4a4b = { 1e 23 [2] 6a 3b [2] 2d 39 [2] 6a 28 [2] 24 24 [2] 28 2e [2] 3f 25 [2] 24 6b [2] 19 }

  condition:
    any of them
}