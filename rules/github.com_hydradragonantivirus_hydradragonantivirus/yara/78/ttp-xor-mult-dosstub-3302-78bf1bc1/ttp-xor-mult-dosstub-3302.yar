rule TTP_XOR_MULT_DOSStub_3302 {
  strings:
    $key_3302 = { 67 6a [2] 13 72 [2] 54 70 [2] 13 61 [2] 5d 6d [2] 51 67 [2] 46 6c [2] 5d 22 [2] 60 }

  condition:
    any of them
}