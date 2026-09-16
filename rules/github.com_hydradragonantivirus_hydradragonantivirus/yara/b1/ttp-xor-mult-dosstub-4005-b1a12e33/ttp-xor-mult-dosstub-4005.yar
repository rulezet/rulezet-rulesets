rule TTP_XOR_MULT_DOSStub_4005 {
  strings:
    $key_4005 = { 14 6d [2] 60 75 [2] 27 77 [2] 60 66 [2] 2e 6a [2] 22 60 [2] 35 6b [2] 2e 25 [2] 13 }

  condition:
    any of them
}