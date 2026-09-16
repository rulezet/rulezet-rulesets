rule TTP_XOR_MULT_DOSStub_d048 {
  strings:
    $key_d048 = { 84 20 [2] f0 38 [2] b7 3a [2] f0 2b [2] be 27 [2] b2 2d [2] a5 26 [2] be 68 [2] 83 }

  condition:
    any of them
}