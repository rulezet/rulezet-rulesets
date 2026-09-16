rule TTP_XOR_MULT_DOSStub_4633 {
  strings:
    $key_4633 = { 12 5b [2] 66 43 [2] 21 41 [2] 66 50 [2] 28 5c [2] 24 56 [2] 33 5d [2] 28 13 [2] 15 }

  condition:
    any of them
}