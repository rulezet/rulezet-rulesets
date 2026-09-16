rule TTP_XOR_MULT_DOSStub_67aa {
  strings:
    $key_67aa = { 33 c2 [2] 47 da [2] 00 d8 [2] 47 c9 [2] 09 c5 [2] 05 cf [2] 12 c4 [2] 09 8a [2] 34 }

  condition:
    any of them
}