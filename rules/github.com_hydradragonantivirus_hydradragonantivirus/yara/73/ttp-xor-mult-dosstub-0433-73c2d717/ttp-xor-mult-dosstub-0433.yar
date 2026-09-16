rule TTP_XOR_MULT_DOSStub_0433 {
  strings:
    $key_0433 = { 50 5b [2] 24 43 [2] 63 41 [2] 24 50 [2] 6a 5c [2] 66 56 [2] 71 5d [2] 6a 13 [2] 57 }

  condition:
    any of them
}