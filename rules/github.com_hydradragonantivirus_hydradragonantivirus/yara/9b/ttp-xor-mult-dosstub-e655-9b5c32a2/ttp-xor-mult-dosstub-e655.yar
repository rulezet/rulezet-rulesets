rule TTP_XOR_MULT_DOSStub_e655 {
  strings:
    $key_e655 = { b2 3d [2] c6 25 [2] 81 27 [2] c6 36 [2] 88 3a [2] 84 30 [2] 93 3b [2] 88 75 [2] b5 }

  condition:
    any of them
}