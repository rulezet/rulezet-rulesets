rule TTP_XOR_MULT_DOSStub_7705 {
  strings:
    $key_7705 = { 23 6d [2] 57 75 [2] 10 77 [2] 57 66 [2] 19 6a [2] 15 60 [2] 02 6b [2] 19 25 [2] 24 }

  condition:
    any of them
}