rule TTP_XOR_MULT_DOSStub_d054 {
  strings:
    $key_d054 = { 84 3c [2] f0 24 [2] b7 26 [2] f0 37 [2] be 3b [2] b2 31 [2] a5 3a [2] be 74 [2] 83 }

  condition:
    any of them
}