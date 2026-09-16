rule TTP_XOR_MULT_DOSStub_c8aa {
  strings:
    $key_c8aa = { 9c c2 [2] e8 da [2] af d8 [2] e8 c9 [2] a6 c5 [2] aa cf [2] bd c4 [2] a6 8a [2] 9b }

  condition:
    any of them
}