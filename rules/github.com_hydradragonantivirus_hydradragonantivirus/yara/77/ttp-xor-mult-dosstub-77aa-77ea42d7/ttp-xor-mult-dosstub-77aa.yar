rule TTP_XOR_MULT_DOSStub_77aa {
  strings:
    $key_77aa = { 23 c2 [2] 57 da [2] 10 d8 [2] 57 c9 [2] 19 c5 [2] 15 cf [2] 02 c4 [2] 19 8a [2] 24 }

  condition:
    any of them
}