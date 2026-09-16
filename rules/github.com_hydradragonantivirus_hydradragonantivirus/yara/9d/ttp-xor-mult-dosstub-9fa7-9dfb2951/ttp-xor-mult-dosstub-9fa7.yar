rule TTP_XOR_MULT_DOSStub_9fa7 {
  strings:
    $key_9fa7 = { cb cf [2] bf d7 [2] f8 d5 [2] bf c4 [2] f1 c8 [2] fd c2 [2] ea c9 [2] f1 87 [2] cc }

  condition:
    any of them
}