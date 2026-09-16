rule TTP_XOR_MULT_DOSStub_4155 {
  strings:
    $key_4155 = { 15 3d [2] 61 25 [2] 26 27 [2] 61 36 [2] 2f 3a [2] 23 30 [2] 34 3b [2] 2f 75 [2] 12 }

  condition:
    any of them
}