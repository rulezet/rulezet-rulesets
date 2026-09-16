rule TTP_XOR_MULT_DOSStub_d755 {
  strings:
    $key_d755 = { 83 3d [2] f7 25 [2] b0 27 [2] f7 36 [2] b9 3a [2] b5 30 [2] a2 3b [2] b9 75 [2] 84 }

  condition:
    any of them
}