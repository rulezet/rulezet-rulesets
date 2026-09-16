rule TTP_XOR_MULT_DOSStub_d742 {
  strings:
    $key_d742 = { 83 2a [2] f7 32 [2] b0 30 [2] f7 21 [2] b9 2d [2] b5 27 [2] a2 2c [2] b9 62 [2] 84 }

  condition:
    any of them
}