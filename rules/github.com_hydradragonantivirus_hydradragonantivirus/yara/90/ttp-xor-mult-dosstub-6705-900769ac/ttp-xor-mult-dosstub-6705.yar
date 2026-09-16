rule TTP_XOR_MULT_DOSStub_6705 {
  strings:
    $key_6705 = { 33 6d [2] 47 75 [2] 00 77 [2] 47 66 [2] 09 6a [2] 05 60 [2] 12 6b [2] 09 25 [2] 34 }

  condition:
    any of them
}