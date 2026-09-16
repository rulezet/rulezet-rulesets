rule TTP_XOR_MULT_DOSStub_6358 {
  strings:
    $key_6358 = { 37 30 [2] 43 28 [2] 04 2a [2] 43 3b [2] 0d 37 [2] 01 3d [2] 16 36 [2] 0d 78 [2] 30 }

  condition:
    any of them
}