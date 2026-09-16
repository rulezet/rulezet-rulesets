rule TTP_XOR_MULT_DOSStub_7759 {
  strings:
    $key_7759 = { 23 31 [2] 57 29 [2] 10 2b [2] 57 3a [2] 19 36 [2] 15 3c [2] 02 37 [2] 19 79 [2] 24 }

  condition:
    any of them
}