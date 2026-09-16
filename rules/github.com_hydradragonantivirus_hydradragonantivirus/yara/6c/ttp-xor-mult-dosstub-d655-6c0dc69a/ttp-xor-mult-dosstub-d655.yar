rule TTP_XOR_MULT_DOSStub_d655 {
  strings:
    $key_d655 = { 82 3d [2] f6 25 [2] b1 27 [2] f6 36 [2] b8 3a [2] b4 30 [2] a3 3b [2] b8 75 [2] 85 }

  condition:
    any of them
}