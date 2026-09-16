rule TTP_XOR_MULT_DOSStub_c7aa {
  strings:
    $key_c7aa = { 93 c2 [2] e7 da [2] a0 d8 [2] e7 c9 [2] a9 c5 [2] a5 cf [2] b2 c4 [2] a9 8a [2] 94 }

  condition:
    any of them
}