rule TTP_XOR_MULT_DOSStub_a8aa {
  strings:
    $key_a8aa = { fc c2 [2] 88 da [2] cf d8 [2] 88 c9 [2] c6 c5 [2] ca cf [2] dd c4 [2] c6 8a [2] fb }

  condition:
    any of them
}