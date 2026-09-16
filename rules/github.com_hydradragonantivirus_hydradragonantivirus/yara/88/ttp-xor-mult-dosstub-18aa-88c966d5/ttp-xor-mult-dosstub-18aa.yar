rule TTP_XOR_MULT_DOSStub_18aa {
  strings:
    $key_18aa = { 4c c2 [2] 38 da [2] 7f d8 [2] 38 c9 [2] 76 c5 [2] 7a cf [2] 6d c4 [2] 76 8a [2] 4b }

  condition:
    any of them
}