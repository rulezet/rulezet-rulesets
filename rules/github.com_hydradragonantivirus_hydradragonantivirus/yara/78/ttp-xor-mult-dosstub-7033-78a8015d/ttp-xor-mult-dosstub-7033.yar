rule TTP_XOR_MULT_DOSStub_7033 {
  strings:
    $key_7033 = { 24 5b [2] 50 43 [2] 17 41 [2] 50 50 [2] 1e 5c [2] 12 56 [2] 05 5d [2] 1e 13 [2] 23 }

  condition:
    any of them
}