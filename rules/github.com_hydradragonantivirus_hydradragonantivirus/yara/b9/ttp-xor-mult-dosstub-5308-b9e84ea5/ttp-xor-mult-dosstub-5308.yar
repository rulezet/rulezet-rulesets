rule TTP_XOR_MULT_DOSStub_5308 {
  strings:
    $key_5308 = { 07 60 [2] 73 78 [2] 34 7a [2] 73 6b [2] 3d 67 [2] 31 6d [2] 26 66 [2] 3d 28 [2] 00 }

  condition:
    any of them
}