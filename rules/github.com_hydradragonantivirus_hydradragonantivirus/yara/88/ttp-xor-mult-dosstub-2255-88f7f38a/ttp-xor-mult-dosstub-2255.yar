rule TTP_XOR_MULT_DOSStub_2255 {
  strings:
    $key_2255 = { 76 3d [2] 02 25 [2] 45 27 [2] 02 36 [2] 4c 3a [2] 40 30 [2] 57 3b [2] 4c 75 [2] 71 }

  condition:
    any of them
}