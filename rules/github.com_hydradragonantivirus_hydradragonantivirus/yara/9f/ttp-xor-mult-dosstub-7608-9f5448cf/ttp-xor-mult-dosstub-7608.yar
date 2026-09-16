rule TTP_XOR_MULT_DOSStub_7608 {
  strings:
    $key_7608 = { 22 60 [2] 56 78 [2] 11 7a [2] 56 6b [2] 18 67 [2] 14 6d [2] 03 66 [2] 18 28 [2] 25 }

  condition:
    any of them
}