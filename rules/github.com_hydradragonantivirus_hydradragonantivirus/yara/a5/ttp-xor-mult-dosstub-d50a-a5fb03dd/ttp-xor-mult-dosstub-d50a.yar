rule TTP_XOR_MULT_DOSStub_d50a {
  strings:
    $key_d50a = { 81 62 [2] f5 7a [2] b2 78 [2] f5 69 [2] bb 65 [2] b7 6f [2] a0 64 [2] bb 2a [2] 86 }

  condition:
    any of them
}