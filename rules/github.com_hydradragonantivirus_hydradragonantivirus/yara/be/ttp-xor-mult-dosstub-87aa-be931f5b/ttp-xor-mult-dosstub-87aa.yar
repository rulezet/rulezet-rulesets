rule TTP_XOR_MULT_DOSStub_87aa {
  strings:
    $key_87aa = { d3 c2 [2] a7 da [2] e0 d8 [2] a7 c9 [2] e9 c5 [2] e5 cf [2] f2 c4 [2] e9 8a [2] d4 }

  condition:
    any of them
}