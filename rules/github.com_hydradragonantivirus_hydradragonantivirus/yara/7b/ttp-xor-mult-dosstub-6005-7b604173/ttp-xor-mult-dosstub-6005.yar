rule TTP_XOR_MULT_DOSStub_6005 {
  strings:
    $key_6005 = { 34 6d [2] 40 75 [2] 07 77 [2] 40 66 [2] 0e 6a [2] 02 60 [2] 15 6b [2] 0e 25 [2] 33 }

  condition:
    any of them
}