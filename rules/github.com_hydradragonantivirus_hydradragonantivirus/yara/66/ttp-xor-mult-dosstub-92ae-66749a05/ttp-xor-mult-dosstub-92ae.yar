rule TTP_XOR_MULT_DOSStub_92ae {
  strings:
    $key_92ae = { c6 c6 [2] b2 de [2] f5 dc [2] b2 cd [2] fc c1 [2] f0 cb [2] e7 c0 [2] fc 8e [2] c1 }

  condition:
    any of them
}