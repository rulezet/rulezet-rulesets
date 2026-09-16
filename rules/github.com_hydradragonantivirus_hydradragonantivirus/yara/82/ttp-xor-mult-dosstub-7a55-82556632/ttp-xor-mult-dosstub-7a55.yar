rule TTP_XOR_MULT_DOSStub_7a55 {
  strings:
    $key_7a55 = { 2e 3d [2] 5a 25 [2] 1d 27 [2] 5a 36 [2] 14 3a [2] 18 30 [2] 0f 3b [2] 14 75 [2] 29 }

  condition:
    any of them
}