rule TTP_XOR_MULT_DOSStub_abaa {
  strings:
    $key_abaa = { ff c2 [2] 8b da [2] cc d8 [2] 8b c9 [2] c5 c5 [2] c9 cf [2] de c4 [2] c5 8a [2] f8 }

  condition:
    any of them
}