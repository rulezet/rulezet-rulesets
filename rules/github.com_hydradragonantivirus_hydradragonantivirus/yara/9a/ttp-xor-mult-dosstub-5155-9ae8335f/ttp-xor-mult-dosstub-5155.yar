rule TTP_XOR_MULT_DOSStub_5155 {
  strings:
    $key_5155 = { 05 3d [2] 71 25 [2] 36 27 [2] 71 36 [2] 3f 3a [2] 33 30 [2] 24 3b [2] 3f 75 [2] 02 }

  condition:
    any of them
}