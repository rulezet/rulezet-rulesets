rule TTP_XOR_MULT_DOSStub_c7bf {
  strings:
    $key_c7bf = { 93 d7 [2] e7 cf [2] a0 cd [2] e7 dc [2] a9 d0 [2] a5 da [2] b2 d1 [2] a9 9f [2] 94 }

  condition:
    any of them
}