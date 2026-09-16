rule TTP_XOR_MULT_DOSStub_d54a {
  strings:
    $key_d54a = { 81 22 [2] f5 3a [2] b2 38 [2] f5 29 [2] bb 25 [2] b7 2f [2] a0 24 [2] bb 6a [2] 86 }

  condition:
    any of them
}