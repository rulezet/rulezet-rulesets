rule TTP_XOR_MULT_DOSStub_b3aa {
  strings:
    $key_b3aa = { e7 c2 [2] 93 da [2] d4 d8 [2] 93 c9 [2] dd c5 [2] d1 cf [2] c6 c4 [2] dd 8a [2] e0 }

  condition:
    any of them
}