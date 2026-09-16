rule TTP_XOR_MULT_DOSStub_3555 {
  strings:
    $key_3555 = { 61 3d [2] 15 25 [2] 52 27 [2] 15 36 [2] 5b 3a [2] 57 30 [2] 40 3b [2] 5b 75 [2] 66 }

  condition:
    any of them
}