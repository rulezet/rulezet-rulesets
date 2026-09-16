rule TTP_XOR_MULT_DOSStub_78aa {
  strings:
    $key_78aa = { 2c c2 [2] 58 da [2] 1f d8 [2] 58 c9 [2] 16 c5 [2] 1a cf [2] 0d c4 [2] 16 8a [2] 2b }

  condition:
    any of them
}