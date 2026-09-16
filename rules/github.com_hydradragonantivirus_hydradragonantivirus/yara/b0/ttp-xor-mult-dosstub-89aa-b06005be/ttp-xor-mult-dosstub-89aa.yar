rule TTP_XOR_MULT_DOSStub_89aa {
  strings:
    $key_89aa = { dd c2 [2] a9 da [2] ee d8 [2] a9 c9 [2] e7 c5 [2] eb cf [2] fc c4 [2] e7 8a [2] da }

  condition:
    any of them
}