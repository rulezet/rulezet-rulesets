rule TTP_XOR_MULT_DOSStub_3334 {
  strings:
    $key_3334 = { 67 5c [2] 13 44 [2] 54 46 [2] 13 57 [2] 5d 5b [2] 51 51 [2] 46 5a [2] 5d 14 [2] 60 }

  condition:
    any of them
}