rule TTP_XOR_MULT_DOSStub_a6ab {
  strings:
    $key_a6ab = { f2 c3 [2] 86 db [2] c1 d9 [2] 86 c8 [2] c8 c4 [2] c4 ce [2] d3 c5 [2] c8 8b [2] f5 }

  condition:
    any of them
}