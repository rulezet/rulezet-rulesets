rule TTP_XOR_MULT_DOSStub_7302 {
  strings:
    $key_7302 = { 27 6a [2] 53 72 [2] 14 70 [2] 53 61 [2] 1d 6d [2] 11 67 [2] 06 6c [2] 1d 22 [2] 20 }

  condition:
    any of them
}