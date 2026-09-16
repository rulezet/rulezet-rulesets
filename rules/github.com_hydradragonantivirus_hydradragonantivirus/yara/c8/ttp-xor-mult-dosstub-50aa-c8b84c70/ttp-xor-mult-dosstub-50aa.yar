rule TTP_XOR_MULT_DOSStub_50aa {
  strings:
    $key_50aa = { 04 c2 [2] 70 da [2] 37 d8 [2] 70 c9 [2] 3e c5 [2] 32 cf [2] 25 c4 [2] 3e 8a [2] 03 }

  condition:
    any of them
}