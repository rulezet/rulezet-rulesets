rule TTP_XOR_MULT_DOSStub_7048 {
  strings:
    $key_7048 = { 24 20 [2] 50 38 [2] 17 3a [2] 50 2b [2] 1e 27 [2] 12 2d [2] 05 26 [2] 1e 68 [2] 23 }

  condition:
    any of them
}