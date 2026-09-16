rule TTP_XOR_MULT_DOSStub_2352 {
  strings:
    $key_2352 = { 77 3a [2] 03 22 [2] 44 20 [2] 03 31 [2] 4d 3d [2] 41 37 [2] 56 3c [2] 4d 72 [2] 70 }

  condition:
    any of them
}