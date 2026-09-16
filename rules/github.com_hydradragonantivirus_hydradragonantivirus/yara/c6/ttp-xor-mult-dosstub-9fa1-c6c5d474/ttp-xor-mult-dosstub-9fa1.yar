rule TTP_XOR_MULT_DOSStub_9fa1 {
  strings:
    $key_9fa1 = { cb c9 [2] bf d1 [2] f8 d3 [2] bf c2 [2] f1 ce [2] fd c4 [2] ea cf [2] f1 81 [2] cc }

  condition:
    any of them
}