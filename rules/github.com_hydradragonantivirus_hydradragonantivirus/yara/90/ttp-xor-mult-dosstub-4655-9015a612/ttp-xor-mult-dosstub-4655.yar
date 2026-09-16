rule TTP_XOR_MULT_DOSStub_4655 {
  strings:
    $key_4655 = { 12 3d [2] 66 25 [2] 21 27 [2] 66 36 [2] 28 3a [2] 24 30 [2] 33 3b [2] 28 75 [2] 15 }

  condition:
    any of them
}