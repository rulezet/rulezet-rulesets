rule TTP_XOR_MULT_DOSStub_7755 {
  strings:
    $key_7755 = { 23 3d [2] 57 25 [2] 10 27 [2] 57 36 [2] 19 3a [2] 15 30 [2] 02 3b [2] 19 75 [2] 24 }

  condition:
    any of them
}