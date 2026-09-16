rule TTP_XOR_MULT_DOSStub_d5bf {
  strings:
    $key_d5bf = { 81 d7 [2] f5 cf [2] b2 cd [2] f5 dc [2] bb d0 [2] b7 da [2] a0 d1 [2] bb 9f [2] 86 }

  condition:
    any of them
}