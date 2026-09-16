rule TTP_XOR_MULT_DOSStub_5354 {
  strings:
    $key_5354 = { 07 3c [2] 73 24 [2] 34 26 [2] 73 37 [2] 3d 3b [2] 31 31 [2] 26 3a [2] 3d 74 [2] 00 }

  condition:
    any of them
}