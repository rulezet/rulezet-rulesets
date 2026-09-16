rule TTP_XOR_MULT_DOSStub_caaa {
  strings:
    $key_caaa = { 9e c2 [2] ea da [2] ad d8 [2] ea c9 [2] a4 c5 [2] a8 cf [2] bf c4 [2] a4 8a [2] 99 }

  condition:
    any of them
}