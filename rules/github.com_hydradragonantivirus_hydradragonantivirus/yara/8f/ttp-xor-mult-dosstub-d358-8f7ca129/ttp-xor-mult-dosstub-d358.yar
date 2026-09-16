rule TTP_XOR_MULT_DOSStub_d358 {
  strings:
    $key_d358 = { 87 30 [2] f3 28 [2] b4 2a [2] f3 3b [2] bd 37 [2] b1 3d [2] a6 36 [2] bd 78 [2] 80 }

  condition:
    any of them
}