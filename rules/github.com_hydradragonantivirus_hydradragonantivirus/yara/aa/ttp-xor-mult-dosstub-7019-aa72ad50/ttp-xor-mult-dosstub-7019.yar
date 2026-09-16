rule TTP_XOR_MULT_DOSStub_7019 {
  strings:
    $key_7019 = { 24 71 [2] 50 69 [2] 17 6b [2] 50 7a [2] 1e 76 [2] 12 7c [2] 05 77 [2] 1e 39 [2] 23 }

  condition:
    any of them
}