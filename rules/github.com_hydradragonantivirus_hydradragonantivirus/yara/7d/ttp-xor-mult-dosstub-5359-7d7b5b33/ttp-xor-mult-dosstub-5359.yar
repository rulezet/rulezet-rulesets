rule TTP_XOR_MULT_DOSStub_5359 {
  strings:
    $key_5359 = { 07 31 [2] 73 29 [2] 34 2b [2] 73 3a [2] 3d 36 [2] 31 3c [2] 26 37 [2] 3d 79 [2] 00 }

  condition:
    any of them
}