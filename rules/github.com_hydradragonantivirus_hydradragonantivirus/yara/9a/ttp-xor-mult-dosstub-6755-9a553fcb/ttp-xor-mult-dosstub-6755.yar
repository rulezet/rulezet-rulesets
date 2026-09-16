rule TTP_XOR_MULT_DOSStub_6755 {
  strings:
    $key_6755 = { 33 3d [2] 47 25 [2] 00 27 [2] 47 36 [2] 09 3a [2] 05 30 [2] 12 3b [2] 09 75 [2] 34 }

  condition:
    any of them
}