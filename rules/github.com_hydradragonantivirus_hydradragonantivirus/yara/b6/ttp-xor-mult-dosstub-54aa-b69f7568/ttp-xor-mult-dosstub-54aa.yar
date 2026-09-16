rule TTP_XOR_MULT_DOSStub_54aa {
  strings:
    $key_54aa = { 00 c2 [2] 74 da [2] 33 d8 [2] 74 c9 [2] 3a c5 [2] 36 cf [2] 21 c4 [2] 3a 8a [2] 07 }

  condition:
    any of them
}