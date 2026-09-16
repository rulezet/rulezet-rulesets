rule TTP_XOR_MULT_DOSStub_2358 {
  strings:
    $key_2358 = { 77 30 [2] 03 28 [2] 44 2a [2] 03 3b [2] 4d 37 [2] 41 3d [2] 56 36 [2] 4d 78 [2] 70 }

  condition:
    any of them
}