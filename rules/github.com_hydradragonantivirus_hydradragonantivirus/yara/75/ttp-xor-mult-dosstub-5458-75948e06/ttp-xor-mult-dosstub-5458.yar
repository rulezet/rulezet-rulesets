rule TTP_XOR_MULT_DOSStub_5458 {
  strings:
    $key_5458 = { 00 30 [2] 74 28 [2] 33 2a [2] 74 3b [2] 3a 37 [2] 36 3d [2] 21 36 [2] 3a 78 [2] 07 }

  condition:
    any of them
}