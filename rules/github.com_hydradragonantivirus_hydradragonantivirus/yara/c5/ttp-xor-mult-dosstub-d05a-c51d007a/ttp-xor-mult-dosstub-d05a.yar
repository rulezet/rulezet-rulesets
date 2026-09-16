rule TTP_XOR_MULT_DOSStub_d05a {
  strings:
    $key_d05a = { 84 32 [2] f0 2a [2] b7 28 [2] f0 39 [2] be 35 [2] b2 3f [2] a5 34 [2] be 7a [2] 83 }

  condition:
    any of them
}