rule TTP_XOR_MULT_DOSStub_8daa {
  strings:
    $key_8daa = { d9 c2 [2] ad da [2] ea d8 [2] ad c9 [2] e3 c5 [2] ef cf [2] f8 c4 [2] e3 8a [2] de }

  condition:
    any of them
}