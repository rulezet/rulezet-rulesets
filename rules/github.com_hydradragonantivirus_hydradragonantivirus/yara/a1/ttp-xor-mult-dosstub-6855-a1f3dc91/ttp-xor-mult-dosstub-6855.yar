rule TTP_XOR_MULT_DOSStub_6855 {
  strings:
    $key_6855 = { 3c 3d [2] 48 25 [2] 0f 27 [2] 48 36 [2] 06 3a [2] 0a 30 [2] 1d 3b [2] 06 75 [2] 3b }

  condition:
    any of them
}