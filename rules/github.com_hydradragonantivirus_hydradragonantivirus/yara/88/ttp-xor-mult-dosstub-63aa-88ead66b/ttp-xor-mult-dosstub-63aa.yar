rule TTP_XOR_MULT_DOSStub_63aa {
  strings:
    $key_63aa = { 37 c2 [2] 43 da [2] 04 d8 [2] 43 c9 [2] 0d c5 [2] 01 cf [2] 16 c4 [2] 0d 8a [2] 30 }

  condition:
    any of them
}