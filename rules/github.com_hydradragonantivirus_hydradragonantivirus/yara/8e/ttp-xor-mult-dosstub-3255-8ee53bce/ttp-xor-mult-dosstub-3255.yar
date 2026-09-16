rule TTP_XOR_MULT_DOSStub_3255 {
  strings:
    $key_3255 = { 66 3d [2] 12 25 [2] 55 27 [2] 12 36 [2] 5c 3a [2] 50 30 [2] 47 3b [2] 5c 75 [2] 61 }

  condition:
    any of them
}