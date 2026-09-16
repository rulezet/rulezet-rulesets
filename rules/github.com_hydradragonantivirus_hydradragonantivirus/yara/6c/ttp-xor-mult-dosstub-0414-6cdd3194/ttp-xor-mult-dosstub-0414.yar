rule TTP_XOR_MULT_DOSStub_0414 {
  strings:
    $key_0414 = { 50 7c [2] 24 64 [2] 63 66 [2] 24 77 [2] 6a 7b [2] 66 71 [2] 71 7a [2] 6a 34 [2] 57 }

  condition:
    any of them
}