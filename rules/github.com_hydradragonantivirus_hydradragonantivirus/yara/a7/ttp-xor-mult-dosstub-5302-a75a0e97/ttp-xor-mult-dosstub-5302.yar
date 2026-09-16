rule TTP_XOR_MULT_DOSStub_5302 {
  strings:
    $key_5302 = { 07 6a [2] 73 72 [2] 34 70 [2] 73 61 [2] 3d 6d [2] 31 67 [2] 26 6c [2] 3d 22 [2] 00 }

  condition:
    any of them
}