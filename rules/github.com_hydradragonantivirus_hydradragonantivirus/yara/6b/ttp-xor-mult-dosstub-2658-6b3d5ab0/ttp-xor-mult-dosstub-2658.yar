rule TTP_XOR_MULT_DOSStub_2658 {
  strings:
    $key_2658 = { 72 30 [2] 06 28 [2] 41 2a [2] 06 3b [2] 48 37 [2] 44 3d [2] 53 36 [2] 48 78 [2] 75 }

  condition:
    any of them
}