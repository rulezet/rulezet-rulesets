rule TTP_XOR_MULT_DOSStub_9a8b {
  strings:
    $key_9a8b = { ce e3 [2] ba fb [2] fd f9 [2] ba e8 [2] f4 e4 [2] f8 ee [2] ef e5 [2] f4 ab [2] c9 }

  condition:
    any of them
}