rule TTP_XOR_MULT_DOSStub_0455 {
  strings:
    $key_0455 = { 50 3d [2] 24 25 [2] 63 27 [2] 24 36 [2] 6a 3a [2] 66 30 [2] 71 3b [2] 6a 75 [2] 57 }

  condition:
    any of them
}