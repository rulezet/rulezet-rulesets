rule TTP_XOR_MULT_DOSStub_12aa {
  strings:
    $key_12aa = { 46 c2 [2] 32 da [2] 75 d8 [2] 32 c9 [2] 7c c5 [2] 70 cf [2] 67 c4 [2] 7c 8a [2] 41 }

  condition:
    any of them
}