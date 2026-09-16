rule TTP_XOR_MULT_DOSStub_36aa {
  strings:
    $key_36aa = { 62 c2 [2] 16 da [2] 51 d8 [2] 16 c9 [2] 58 c5 [2] 54 cf [2] 43 c4 [2] 58 8a [2] 65 }

  condition:
    any of them
}