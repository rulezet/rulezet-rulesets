rule TTP_XOR_MULT_DOSStub_08aa {
  strings:
    $key_08aa = { 5c c2 [2] 28 da [2] 6f d8 [2] 28 c9 [2] 66 c5 [2] 6a cf [2] 7d c4 [2] 66 8a [2] 5b }

  condition:
    any of them
}