rule TTP_XOR_MULT_DOSStub_03aa {
  strings:
    $key_03aa = { 57 c2 [2] 23 da [2] 64 d8 [2] 23 c9 [2] 6d c5 [2] 61 cf [2] 76 c4 [2] 6d 8a [2] 50 }

  condition:
    any of them
}