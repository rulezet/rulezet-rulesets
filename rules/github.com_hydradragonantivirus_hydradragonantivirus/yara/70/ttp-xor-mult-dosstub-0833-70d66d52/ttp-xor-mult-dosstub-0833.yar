rule TTP_XOR_MULT_DOSStub_0833 {
  strings:
    $key_0833 = { 5c 5b [2] 28 43 [2] 6f 41 [2] 28 50 [2] 66 5c [2] 6a 56 [2] 7d 5d [2] 66 13 [2] 5b }

  condition:
    any of them
}