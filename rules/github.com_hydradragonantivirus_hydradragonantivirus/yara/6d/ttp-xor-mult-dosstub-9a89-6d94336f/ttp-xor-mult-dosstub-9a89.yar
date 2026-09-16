rule TTP_XOR_MULT_DOSStub_9a89 {
  strings:
    $key_9a89 = { ce e1 [2] ba f9 [2] fd fb [2] ba ea [2] f4 e6 [2] f8 ec [2] ef e7 [2] f4 a9 [2] c9 }

  condition:
    any of them
}