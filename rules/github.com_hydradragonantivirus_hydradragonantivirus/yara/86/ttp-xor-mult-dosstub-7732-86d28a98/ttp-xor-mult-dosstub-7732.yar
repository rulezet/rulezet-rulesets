rule TTP_XOR_MULT_DOSStub_7732 {
  strings:
    $key_7732 = { 23 5a [2] 57 42 [2] 10 40 [2] 57 51 [2] 19 5d [2] 15 57 [2] 02 5c [2] 19 12 [2] 24 }

  condition:
    any of them
}