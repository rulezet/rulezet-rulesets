rule TTP_XOR_MULT_DOSStub_5a4b {
  strings:
    $key_5a4b = { 0e 23 [2] 7a 3b [2] 3d 39 [2] 7a 28 [2] 34 24 [2] 38 2e [2] 2f 25 [2] 34 6b [2] 09 }

  condition:
    any of them
}