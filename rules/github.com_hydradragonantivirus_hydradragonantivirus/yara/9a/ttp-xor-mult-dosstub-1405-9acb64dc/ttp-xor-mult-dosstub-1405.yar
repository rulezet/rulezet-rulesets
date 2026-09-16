rule TTP_XOR_MULT_DOSStub_1405 {
  strings:
    $key_1405 = { 40 6d [2] 34 75 [2] 73 77 [2] 34 66 [2] 7a 6a [2] 76 60 [2] 61 6b [2] 7a 25 [2] 47 }

  condition:
    any of them
}