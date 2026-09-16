rule TTP_XOR_MULT_DOSStub_d044 {
  strings:
    $key_d044 = { 84 2c [2] f0 34 [2] b7 36 [2] f0 27 [2] be 2b [2] b2 21 [2] a5 2a [2] be 64 [2] 83 }

  condition:
    any of them
}