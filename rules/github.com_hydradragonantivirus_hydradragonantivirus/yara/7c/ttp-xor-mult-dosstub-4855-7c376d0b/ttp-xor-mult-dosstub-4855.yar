rule TTP_XOR_MULT_DOSStub_4855 {
  strings:
    $key_4855 = { 1c 3d [2] 68 25 [2] 2f 27 [2] 68 36 [2] 26 3a [2] 2a 30 [2] 3d 3b [2] 26 75 [2] 1b }

  condition:
    any of them
}