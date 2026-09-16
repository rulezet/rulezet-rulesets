rule TTP_XOR_MULT_DOSStub_92a8 {
  strings:
    $key_92a8 = { c6 c0 [2] b2 d8 [2] f5 da [2] b2 cb [2] fc c7 [2] f0 cd [2] e7 c6 [2] fc 88 [2] c1 }

  condition:
    any of them
}