rule TTP_XOR_MULT_DOSStub_d59a {
  strings:
    $key_d59a = { 81 f2 [2] f5 ea [2] b2 e8 [2] f5 f9 [2] bb f5 [2] b7 ff [2] a0 f4 [2] bb ba [2] 86 }

  condition:
    any of them
}