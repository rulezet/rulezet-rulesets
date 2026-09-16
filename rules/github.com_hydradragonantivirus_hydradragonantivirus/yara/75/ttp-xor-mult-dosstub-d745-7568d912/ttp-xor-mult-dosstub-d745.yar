rule TTP_XOR_MULT_DOSStub_d745 {
  strings:
    $key_d745 = { 83 2d [2] f7 35 [2] b0 37 [2] f7 26 [2] b9 2a [2] b5 20 [2] a2 2b [2] b9 65 [2] 84 }

  condition:
    any of them
}