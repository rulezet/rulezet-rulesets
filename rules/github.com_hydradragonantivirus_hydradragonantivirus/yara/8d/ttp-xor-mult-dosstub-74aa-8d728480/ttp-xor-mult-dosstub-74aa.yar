rule TTP_XOR_MULT_DOSStub_74aa {
  strings:
    $key_74aa = { 20 c2 [2] 54 da [2] 13 d8 [2] 54 c9 [2] 1a c5 [2] 16 cf [2] 01 c4 [2] 1a 8a [2] 27 }

  condition:
    any of them
}