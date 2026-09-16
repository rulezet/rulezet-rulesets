rule TTP_XOR_MULT_DOSStub_91c8 {
  strings:
    $key_91c8 = { c5 a0 [2] b1 b8 [2] f6 ba [2] b1 ab [2] ff a7 [2] f3 ad [2] e4 a6 [2] ff e8 [2] c2 }

  condition:
    any of them
}