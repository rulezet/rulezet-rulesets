rule TTP_XOR_MULT_DOSStub_3655 {
  strings:
    $key_3655 = { 62 3d [2] 16 25 [2] 51 27 [2] 16 36 [2] 58 3a [2] 54 30 [2] 43 3b [2] 58 75 [2] 65 }

  condition:
    any of them
}