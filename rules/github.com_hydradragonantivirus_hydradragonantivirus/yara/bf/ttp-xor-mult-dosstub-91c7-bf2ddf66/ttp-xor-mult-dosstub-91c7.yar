rule TTP_XOR_MULT_DOSStub_91c7 {
  strings:
    $key_91c7 = { c5 af [2] b1 b7 [2] f6 b5 [2] b1 a4 [2] ff a8 [2] f3 a2 [2] e4 a9 [2] ff e7 [2] c2 }

  condition:
    any of them
}