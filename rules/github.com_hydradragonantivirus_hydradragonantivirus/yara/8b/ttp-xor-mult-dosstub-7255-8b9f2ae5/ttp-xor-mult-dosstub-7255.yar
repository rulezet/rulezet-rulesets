rule TTP_XOR_MULT_DOSStub_7255 {
  strings:
    $key_7255 = { 26 3d [2] 52 25 [2] 15 27 [2] 52 36 [2] 1c 3a [2] 10 30 [2] 07 3b [2] 1c 75 [2] 21 }

  condition:
    any of them
}