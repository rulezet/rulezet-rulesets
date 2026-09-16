rule TTP_XOR_MULT_DOSStub_7059 {
  strings:
    $key_7059 = { 24 31 [2] 50 29 [2] 17 2b [2] 50 3a [2] 1e 36 [2] 12 3c [2] 05 37 [2] 1e 79 [2] 23 }

  condition:
    any of them
}