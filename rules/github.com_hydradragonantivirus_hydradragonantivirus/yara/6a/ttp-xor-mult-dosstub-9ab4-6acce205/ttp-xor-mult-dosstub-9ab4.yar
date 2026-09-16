rule TTP_XOR_MULT_DOSStub_9ab4 {
  strings:
    $key_9ab4 = { ce dc [2] ba c4 [2] fd c6 [2] ba d7 [2] f4 db [2] f8 d1 [2] ef da [2] f4 94 [2] c9 }

  condition:
    any of them
}