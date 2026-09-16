rule TTP_XOR_MULT_DOSStub_46aa {
  strings:
    $key_46aa = { 12 c2 [2] 66 da [2] 21 d8 [2] 66 c9 [2] 28 c5 [2] 24 cf [2] 33 c4 [2] 28 8a [2] 15 }

  condition:
    any of them
}