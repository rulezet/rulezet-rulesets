rule TTP_XOR_MULT_DOSStub_3155 {
  strings:
    $key_3155 = { 65 3d [2] 11 25 [2] 56 27 [2] 11 36 [2] 5f 3a [2] 53 30 [2] 44 3b [2] 5f 75 [2] 62 }

  condition:
    any of them
}