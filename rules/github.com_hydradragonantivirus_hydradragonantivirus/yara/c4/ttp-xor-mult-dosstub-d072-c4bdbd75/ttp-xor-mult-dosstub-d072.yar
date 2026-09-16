rule TTP_XOR_MULT_DOSStub_d072 {
  strings:
    $key_d072 = { 84 1a [2] f0 02 [2] b7 00 [2] f0 11 [2] be 1d [2] b2 17 [2] a5 1c [2] be 52 [2] 83 }

  condition:
    any of them
}