rule TTP_XOR_MULT_DOSStub_0405 {
  strings:
    $key_0405 = { 50 6d [2] 24 75 [2] 63 77 [2] 24 66 [2] 6a 6a [2] 66 60 [2] 71 6b [2] 6a 25 [2] 57 }

  condition:
    any of them
}