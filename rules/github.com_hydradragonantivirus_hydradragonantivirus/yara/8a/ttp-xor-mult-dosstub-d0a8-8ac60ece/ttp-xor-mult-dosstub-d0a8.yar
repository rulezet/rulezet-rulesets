rule TTP_XOR_MULT_DOSStub_d0a8 {
  strings:
    $key_d0a8 = { 84 c0 [2] f0 d8 [2] b7 da [2] f0 cb [2] be c7 [2] b2 cd [2] a5 c6 [2] be 88 [2] 83 }

  condition:
    any of them
}