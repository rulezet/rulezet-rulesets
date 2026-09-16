rule TTP_XOR_MULT_DOSStub_e7aa {
  strings:
    $key_e7aa = { b3 c2 [2] c7 da [2] 80 d8 [2] c7 c9 [2] 89 c5 [2] 85 cf [2] 92 c4 [2] 89 8a [2] b4 }

  condition:
    any of them
}