rule TTP_XOR_MULT_DOSStub_7625 {
  strings:
    $key_7625 = { 22 4d [2] 56 55 [2] 11 57 [2] 56 46 [2] 18 4a [2] 14 40 [2] 03 4b [2] 18 05 [2] 25 }

  condition:
    any of them
}