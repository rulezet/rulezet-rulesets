rule TTP_XOR_MULT_DOSStub_9ab5 {
  strings:
    $key_9ab5 = { ce dd [2] ba c5 [2] fd c7 [2] ba d6 [2] f4 da [2] f8 d0 [2] ef db [2] f4 95 [2] c9 }

  condition:
    any of them
}