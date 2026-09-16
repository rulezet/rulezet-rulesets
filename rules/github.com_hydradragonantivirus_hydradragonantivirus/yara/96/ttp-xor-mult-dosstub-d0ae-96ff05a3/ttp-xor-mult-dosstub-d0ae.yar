rule TTP_XOR_MULT_DOSStub_d0ae {
  strings:
    $key_d0ae = { 84 c6 [2] f0 de [2] b7 dc [2] f0 cd [2] be c1 [2] b2 cb [2] a5 c0 [2] be 8e [2] 83 }

  condition:
    any of them
}