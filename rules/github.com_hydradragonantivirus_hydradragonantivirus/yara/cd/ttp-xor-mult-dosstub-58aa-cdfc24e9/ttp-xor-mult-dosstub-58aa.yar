rule TTP_XOR_MULT_DOSStub_58aa {
  strings:
    $key_58aa = { 0c c2 [2] 78 da [2] 3f d8 [2] 78 c9 [2] 36 c5 [2] 3a cf [2] 2d c4 [2] 36 8a [2] 0b }

  condition:
    any of them
}