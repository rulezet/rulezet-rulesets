rule TTP_XOR_MULT_DOSStub_85a8 {
  strings:
    $key_85a8 = { d1 c0 [2] a5 d8 [2] e2 da [2] a5 cb [2] eb c7 [2] e7 cd [2] f0 c6 [2] eb 88 [2] d6 }

  condition:
    any of them
}