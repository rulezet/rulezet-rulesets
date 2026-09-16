rule TTP_XOR_MULT_DOSStub_9fa0 {
  strings:
    $key_9fa0 = { cb c8 [2] bf d0 [2] f8 d2 [2] bf c3 [2] f1 cf [2] fd c5 [2] ea ce [2] f1 80 [2] cc }

  condition:
    any of them
}