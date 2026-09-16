rule TTP_XOR_MULT_DOSStub_92bf {
  strings:
    $key_92bf = { c6 d7 [2] b2 cf [2] f5 cd [2] b2 dc [2] fc d0 [2] f0 da [2] e7 d1 [2] fc 9f [2] c1 }

  condition:
    any of them
}