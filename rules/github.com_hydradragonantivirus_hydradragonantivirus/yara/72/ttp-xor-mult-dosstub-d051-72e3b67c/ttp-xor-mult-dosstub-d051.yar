rule TTP_XOR_MULT_DOSStub_d051 {
  strings:
    $key_d051 = { 84 39 [2] f0 21 [2] b7 23 [2] f0 32 [2] be 3e [2] b2 34 [2] a5 3f [2] be 71 [2] 83 }

  condition:
    any of them
}