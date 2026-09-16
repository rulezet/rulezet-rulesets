rule TTP_XOR_MULT_DOSStub_d049 {
  strings:
    $key_d049 = { 84 21 [2] f0 39 [2] b7 3b [2] f0 2a [2] be 26 [2] b2 2c [2] a5 27 [2] be 69 [2] 83 }

  condition:
    any of them
}