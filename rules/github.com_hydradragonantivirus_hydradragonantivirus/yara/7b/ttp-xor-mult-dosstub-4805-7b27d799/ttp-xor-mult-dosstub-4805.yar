rule TTP_XOR_MULT_DOSStub_4805 {
  strings:
    $key_4805 = { 1c 6d [2] 68 75 [2] 2f 77 [2] 68 66 [2] 26 6a [2] 2a 60 [2] 3d 6b [2] 26 25 [2] 1b }

  condition:
    any of them
}