rule TTP_XOR_MULT_DOSStub_3332 {
  strings:
    $key_3332 = { 67 5a [2] 13 42 [2] 54 40 [2] 13 51 [2] 5d 5d [2] 51 57 [2] 46 5c [2] 5d 12 [2] 60 }

  condition:
    any of them
}