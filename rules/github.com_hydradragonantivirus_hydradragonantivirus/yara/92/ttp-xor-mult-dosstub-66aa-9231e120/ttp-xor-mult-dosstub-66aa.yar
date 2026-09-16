rule TTP_XOR_MULT_DOSStub_66aa {
  strings:
    $key_66aa = { 32 c2 [2] 46 da [2] 01 d8 [2] 46 c9 [2] 08 c5 [2] 04 cf [2] 13 c4 [2] 08 8a [2] 35 }

  condition:
    any of them
}