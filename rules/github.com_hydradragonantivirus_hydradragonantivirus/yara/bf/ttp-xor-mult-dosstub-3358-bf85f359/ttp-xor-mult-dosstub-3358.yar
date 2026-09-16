rule TTP_XOR_MULT_DOSStub_3358 {
  strings:
    $key_3358 = { 67 30 [2] 13 28 [2] 54 2a [2] 13 3b [2] 5d 37 [2] 51 3d [2] 46 36 [2] 5d 78 [2] 60 }

  condition:
    any of them
}