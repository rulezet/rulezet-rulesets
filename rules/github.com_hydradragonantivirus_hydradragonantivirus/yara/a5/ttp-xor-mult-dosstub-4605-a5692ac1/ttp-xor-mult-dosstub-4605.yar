rule TTP_XOR_MULT_DOSStub_4605 {
  strings:
    $key_4605 = { 12 6d [2] 66 75 [2] 21 77 [2] 66 66 [2] 28 6a [2] 24 60 [2] 33 6b [2] 28 25 [2] 15 }

  condition:
    any of them
}