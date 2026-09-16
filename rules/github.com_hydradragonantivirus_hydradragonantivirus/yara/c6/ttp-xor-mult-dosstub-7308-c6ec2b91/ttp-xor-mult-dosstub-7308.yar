rule TTP_XOR_MULT_DOSStub_7308 {
  strings:
    $key_7308 = { 27 60 [2] 53 78 [2] 14 7a [2] 53 6b [2] 1d 67 [2] 11 6d [2] 06 66 [2] 1d 28 [2] 20 }

  condition:
    any of them
}