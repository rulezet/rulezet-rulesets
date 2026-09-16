rule TTP_XOR_MULT_DOSStub_5055 {
  strings:
    $key_5055 = { 04 3d [2] 70 25 [2] 37 27 [2] 70 36 [2] 3e 3a [2] 32 30 [2] 25 3b [2] 3e 75 [2] 03 }

  condition:
    any of them
}